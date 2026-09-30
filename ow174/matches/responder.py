"""An ACTIVE game-server instance: it answers the client's UDP connect packets and
records whether the client reacts.

This is the counterpart to matches/instance.py, which only records and never replies.
The point of this module is the single experiment docs/STATE.md was reaching toward:
the client opens a UDP socket to the game server and sends a "connect" frame ~4x/second,
but nothing answers, so it times out after ~10 s. Before we can know the *correct* reply
we need to know whether the client processes *any* reply on this socket at all -- and, if
it does, what in its outbound stream changes when it does. This module makes that testable.

Drop-in: same CLI as ow174.matches.instance, so runtime.py can launch it by changing the
module name in _instance_command from "ow174.matches.instance" to "ow174.matches.responder"
(or copy this over instance.py). Run standalone:

    py -m ow174.matches.responder --directory logs/matches/test --player Researcher --mode 0 --port 3730

The client's connect frame (34 bytes), from the relay TRACE and packets.jsonl:

    off  0  : 12 bytes  per-packet token  (changes every packet -- the "signed" field)
    off 12  :  4 bytes  0x F0000010 LE    (constant command / channel tag)
    off 16  :  4 bytes  sequence u32 LE   (0,1,2,... increments once per packet)
    off 20  : 12 bytes  zero
    off 32  :  2 bytes  0x01 0xAD         (constant footer)

Baseline (no reply): every inbound packet has this exact shape, only `seq` and `token`
change, and the client stops after ~39 packets. So ANY inbound packet whose shape differs
from the baseline -- a new command tag, a nonzero body, a different length, a reset of seq,
or a second source port -- is the client reacting to what we sent. That reaction, not a
guessed "correct" reply, is the result this harness is built to catch.

Replies are experimental guesses (see build_replies / a --reply-plan JSON). None is known to
be correct. Keep START.bat / normal play pointed at instance.py; use this only for testing.
"""

import argparse
import json
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path

CONNECT_CMD = 0xF0000010      # bytes 12:16 of the client's connect frame (LE)
CONNECT_FOOTER = b"\x01\xad"  # bytes 32:34
TOKEN_LEN = 12
FRAME_LEN = 34


def write_state(path, value):
    """Write state.json through a temp file so a reader never sees half a file."""
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def _stop_when_parent_closes_stdin(stop: threading.Event) -> None:
    def wait_for_eof():
        sys.stdin.buffer.read()
        stop.set()

    threading.Thread(target=wait_for_eof, daemon=True).start()


def parse_frame(data: bytes) -> dict | None:
    """Parse a client connect frame, or return None if it is not the shape we know."""
    if len(data) != FRAME_LEN:
        return None
    token = data[0:TOKEN_LEN]
    (cmd,) = struct.unpack_from("<I", data, 12)
    (seq,) = struct.unpack_from("<I", data, 16)
    body = data[20:32]
    footer = data[32:34]
    return {"token": token, "cmd": cmd, "seq": seq, "body": body, "footer": footer}


def frame_shape(data: bytes) -> tuple:
    """A cheap fingerprint of a packet's *structure*, ignoring the fields that always vary
    in the baseline (the token and the sequence number). Two packets with the same shape are
    'the same kind of packet'; a new shape means the client did something new."""
    f = parse_frame(data)
    if f is None:
        return ("len", len(data), data[:2].hex())  # unknown structure: length + first bytes
    return ("connect", f["cmd"], f["footer"].hex(), f["body"] != bytes(12))


def build_replies(frame: dict, plan: list[dict] | None) -> list[bytes]:
    """The candidate reply(ies) to send back for one inbound connect frame.

    With a --reply-plan JSON, each entry is {"hex": "..."} for a literal packet, or
    {"template": "<name>"} for one of the builders below. Placeholders in hex are not
    supported on purpose -- keep experiments explicit and logged.

    The built-in templates are *guesses* at a connectionless handshake accept/challenge:
      echo          send the client's exact frame back unchanged
      echo_seq0     the client's frame but with seq forced to 0 (a 'start at 0' ack)
      accept_cmd    same framing, command tag +1 (0xF0000011) -- a plausible 'accepted' tag
      challenge     same framing, our own 12-byte token in the token field, body carries
                    the client's token echoed back (classic challenge = prove you saw mine)
    """
    if plan is not None:
        out = []
        for step in plan:
            if "hex" in step:
                out.append(bytes.fromhex(step["hex"].replace(" ", "")))
            elif step.get("template"):
                out.extend(_template(step["template"], frame))
        return out
    # Default sweep when no plan is given: one of each template, so a single run tells us
    # whether the client reacts to any of them.
    return (
        _template("echo", frame)
        + _template("echo_seq0", frame)
        + _template("accept_cmd", frame)
        + _template("challenge", frame)
    )


def _template(name: str, f: dict) -> list[bytes]:
    def frame_bytes(token: bytes, cmd: int, seq: int, body: bytes) -> bytes:
        assert len(token) == TOKEN_LEN and len(body) == 12
        return token + struct.pack("<I", cmd) + struct.pack("<I", seq) + body + CONNECT_FOOTER

    if name == "echo":
        return [frame_bytes(f["token"], f["cmd"], f["seq"], f["body"])]
    if name == "echo_seq0":
        return [frame_bytes(f["token"], f["cmd"], 0, f["body"])]
    if name == "accept_cmd":
        return [frame_bytes(f["token"], f["cmd"] + 1, f["seq"], bytes(12))]
    if name == "challenge":
        return [frame_bytes(os.urandom(TOKEN_LEN), f["cmd"], f["seq"], f["token"][:12])]
    return []


def run(directory, host, port, player, mode, control_stdin=False, activity="queue",
        reply_plan=None, reply_after=0):
    directory.mkdir(parents=True, exist_ok=True)
    state_path = directory / "state.json"
    packets_path = directory / "packets.jsonl"
    replies_path = directory / "replies.jsonl"
    stop = threading.Event()
    if control_stdin:
        _stop_when_parent_closes_stdin(stop)

    state = {
        "id": directory.name, "pid": os.getpid(), "player": player,
        "mode": f"0x{mode:016X}", "host": host, "port": port, "activity": activity,
        "state": "starting", "protocol_ready": False,
        "packets_received": 0, "bytes_received": 0,
        "replies_sent": 0, "client_reacted": False, "shapes_seen": [],
        "started_at": time.time(), "last_packet_at": None,
    }

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind((host, port))
        except OSError as error:
            state.update(state="failed", error=str(error))
            write_state(state_path, state)
            return 1
        state.update(port=sock.getsockname()[1], state="listening")
        write_state(state_path, state)
        sock.settimeout(0.2)

        baseline_shape = ("connect", CONNECT_CMD, CONNECT_FOOTER.hex(), False)
        seen_shapes = set()
        plog = packets_path.open("a", encoding="utf-8", buffering=1)
        rlog = replies_path.open("a", encoding="utf-8", buffering=1)
        n = 0
        try:
            while not stop.is_set():
                try:
                    data, peer = sock.recvfrom(65535)
                except TimeoutError:
                    continue
                n += 1
                now = time.time()
                state["packets_received"] = n
                state["bytes_received"] += len(data)
                state["last_packet_at"] = now
                plog.write(json.dumps({"time": now, "peer": list(peer),
                                       "bytes": len(data), "hex": data.hex()}) + "\n")

                shape = frame_shape(data)
                if shape not in seen_shapes:
                    seen_shapes.add(shape)
                    state["shapes_seen"] = [list(s) if isinstance(s, tuple) else s
                                            for s in seen_shapes]
                    if shape != baseline_shape:
                        # The client sent a kind of packet we never see in the no-reply
                        # baseline: it is reacting to something we sent. This is the signal.
                        state["client_reacted"] = True
                        rlog.write(json.dumps({"time": now, "event": "client_reacted",
                                               "shape": list(shape), "peer": list(peer),
                                               "hex": data.hex()}) + "\n")

                frame = parse_frame(data)
                # Send replies once we are `reply_after` packets in (0 = reply immediately).
                if frame is not None and n > reply_after:
                    replies = build_replies(frame, reply_plan)
                    for r in replies:
                        try:
                            sock.sendto(r, peer)
                            state["replies_sent"] += 1
                            rlog.write(json.dumps({"time": time.time(), "event": "sent",
                                                   "to": list(peer), "in_reply_to_seq": frame["seq"],
                                                   "hex": r.hex()}) + "\n")
                        except OSError as e:
                            rlog.write(json.dumps({"time": time.time(), "event": "send_error",
                                                   "error": str(e)}) + "\n")
                write_state(state_path, state)
        finally:
            plog.close()
            rlog.close()

    state.update(state="stopped", stopped_at=time.time())
    write_state(state_path, state)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--player", required=True)
    parser.add_argument("--mode", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--control-stdin", action="store_true")
    parser.add_argument("--activity", choices=("queue", "practice"), default="queue")
    parser.add_argument("--reply-plan", type=Path, default=None,
                        help="JSON list of {'hex':...} or {'template':...} replies to send per frame")
    parser.add_argument("--reply-after", type=int, default=0,
                        help="Only start replying after this many received packets (default 0)")
    args = parser.parse_args()
    plan = json.loads(args.reply_plan.read_text(encoding="utf-8")) if args.reply_plan else None
    return run(args.directory, args.host, args.port, args.player, args.mode,
               args.control_stdin, args.activity, plan, args.reply_after)


if __name__ == "__main__":
    raise SystemExit(main())
