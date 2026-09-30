"""An ACTIVE game-server instance: it answers the client's UDP connect packets with correctly sealed
replies and records whether the client reacts.

The counterpart to matches/instance.py, which only records. runtime.py launches this module by default
on this branch (OW174_GAME_INSTANCE=ow174.matches.instance gets the silent recorder back).

    py -m ow174.matches.responder --directory logs/matches/test --player Researcher --mode 0 --port 3730

What the client sends (34 bytes, ~4 per second, ~39 times, then it gives up):

    off  0  12  AES-256-GCM tag, truncated (see gamecrypto.py): NOT a random token
    off 12   4  0xF0000010 LE    command / channel tag
    off 16   4  sequence u32 LE  (0, 1, 2, ...; also the last 4 bytes of the GCM nonce)
    off 20  12  zero
    off 32   2  01 AD

The relay's recvfrom hook (relay/log/wfd.log, RECVDATA lines) showed the client DOES read every reply
on this socket. The replies of the first responder were dropped because three of its four templates
carried a tag that cannot verify. This version:

  1. identifies the client's cipher from its first packet (gamecrypto.identify) and writes it to
     state.json as client_cipher;
  2. sends reply candidates that are correctly sealed for the likely server-direction ciphers
     (gamecrypto.peer_candidates), most likely first: a set of priority command tags, then a sweep
     of the whole 0xF00000xx low byte, each with a zero body and with the client's seq as an ack;
  3. flags a reaction when the client's stream changes shape (new command, nonzero body, other length,
     another source port) or when it goes quiet early, and records which candidates went out just
     before, in state.json (reaction) and replies.jsonl.

A reply plan (--reply-plan, or the OW174_REPLY_PLAN environment variable, which PRACTICE_REPLIES.bat
sets) replaces the sweep with exact replies. It is a JSON list sent for every packet, or
{"per_packet": [[...], [...]], "then": [...]} for a different list per packet. Each entry is one of
    {"hex": "..."}                                   a literal packet, unsealed
    {"template": "echo"}                             the client's own packet back
    {"sealed": {"cmd": "0xF0000011", "seq": "server" | "client" | 5, "body": "<24 hex>",
                "footer": "01ad", "key": "ce", "prefix": "client"}}
                                                     a sealed packet; see plan_replies for the
                                                     key/prefix names; default: the client's own
"""

import argparse
import json
import os
import socket
import struct
import sys
import threading
import time
from collections import deque
from pathlib import Path

from ow174.matches import gamecrypto
from ow174.matches.gamecrypto import GameCipher

CONNECT_CMD = 0xF0000010  # bytes 12:16 of the client's connect frame (LE)
CONNECT_FOOTER = b"\x01\xad"  # bytes 32:34
TOKEN_LEN = gamecrypto.TAG_LEN
FRAME_LEN = 34
BASELINE_PACKETS = 39  # what the client sends when nothing answers
BASELINE_INTERVAL = 0.26  # seconds between its connect packets
DEFAULT_BURST = 32  # sealed candidates sent per inbound packet

# Command tags tried first: the client's own (a symmetric handshake), its neighbours, and the same low
# byte with other top bits.
PRIORITY_CMDS = (
    0xF0000010,
    0xF0000011,
    0xF0000012,
    0xF0000020,
    0xF0000001,
    0xF0000002,
    0xF0000000,
    0xF0000018,
    0xF0000030,
    0xE0000010,
    0x70000010,
    0x00000010,
)


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
    (cmd,) = struct.unpack_from("<I", data, 12)
    (seq,) = struct.unpack_from("<I", data, 16)
    return {"token": data[0:TOKEN_LEN], "cmd": cmd, "seq": seq, "body": data[20:32], "footer": data[32:34]}


def frame_shape(data: bytes) -> tuple:
    """A fingerprint of a packet's structure, ignoring the fields that always vary in the baseline (the
    tag and the sequence number). A new shape means the client did something new."""
    f = parse_frame(data)
    if f is None:
        return ("len", len(data), data[12:16].hex() if len(data) >= 16 else data[:2].hex())
    return ("connect", f["cmd"], f["footer"].hex(), f["body"] != bytes(12))


def header(cmd: int, seq: int, body: bytes = bytes(12), footer: bytes = CONNECT_FOOTER) -> bytes:
    """The 22 bytes after the tag, in the client's layout."""
    if len(body) != 12:
        raise ValueError("body must be 12 bytes")
    return struct.pack("<II", cmd & 0xFFFFFFFF, seq & 0xFFFFFFFF) + body + footer


class Sweep:
    """Sealed reply candidates in priority order, each cipher with its own seq counter from 0."""

    def __init__(self, ciphers: list[GameCipher]):
        self.ciphers = ciphers
        self.seq = {c.name: 0 for c in ciphers}
        self.index = 0
        self._plan = list(self._order())

    def _order(self):
        top = self.ciphers[:3]
        low_byte = [0xF0000000 | b for b in range(256)]
        seen = set()
        tiers = (
            (top, PRIORITY_CMDS),
            (self.ciphers, PRIORITY_CMDS),
            (top[:1], low_byte),
            (self.ciphers, low_byte),
        )
        for ciphers, cmds in tiers:
            for cmd in cmds:
                for cipher in ciphers:
                    for ack in (False, True):
                        key = (cipher.name, cmd, ack)
                        if key not in seen:
                            seen.add(key)
                            yield cipher, cmd, ack

    def __len__(self):
        return len(self._plan)

    def next(self, client_seq: int) -> tuple[int, GameCipher, int, bool, bytes] | None:
        if self.index >= len(self._plan):
            return None
        cipher, cmd, ack = self._plan[self.index]
        index = self.index
        self.index += 1
        seq = self.seq[cipher.name]
        self.seq[cipher.name] += 1
        body = struct.pack("<I", client_seq) + bytes(8) if ack else bytes(12)
        return index, cipher, cmd, ack, cipher.seal(header(cmd, seq, body))


def _plan_key(value: str | None, client: GameCipher) -> bytes:
    named = {
        "ae": gamecrypto.PROBE_KEY_AE,
        "ce": gamecrypto.PROBE_KEY_CE,
        "zero": bytes(32),
        "client": client.key,
    }
    return client.key if value is None else named.get(value) or bytes.fromhex(value)


def _plan_prefix(value: str | None, client: GameCipher) -> bytes:
    if value is None or value == "client":
        return client.prefix
    if value in gamecrypto.PROBE_U64:
        return struct.pack("<Q", gamecrypto.PROBE_U64[value])
    return bytes(8) if value == "zero" else bytes.fromhex(value)


def plan_steps(plan, packet_index: int) -> list[dict]:
    """The steps a plan sends for the n-th inbound packet (0-based).

    A list is sent for every packet. A dict {"per_packet": [[...], [...], ...], "then": [...]} sends
    per_packet[n] for packet n, and "then" (default: nothing) once per_packet runs out.
    """
    if isinstance(plan, list):
        return plan
    scripted = plan.get("per_packet", [])
    return scripted[packet_index] if packet_index < len(scripted) else plan.get("then", [])


def plan_replies(frame: dict, raw: bytes, plan: list[dict], client: GameCipher | None, server_seq: list[int]):
    """Replies for one inbound frame from a list of plan steps. server_seq is a one-item counter.

    A sealed step's "key" is "ae", "ce", "zero", "client" or 64 hex digits; its "prefix" is "client",
    "zero", a PROBE_U64 name such as "u64_18", or 16 hex digits. Both default to the client's own.
    """
    out = []
    base = client or gamecrypto.ZERO
    for step in plan:
        if "hex" in step:
            out.append(bytes.fromhex(step["hex"].replace(" ", "")))
        elif step.get("template") == "echo":
            out.append(raw)
        elif "sealed" in step:
            s = step["sealed"]
            cipher = GameCipher(_plan_key(s.get("key"), base), _plan_prefix(s.get("prefix"), base), "plan")
            seq_rule = s.get("seq", "server")
            if seq_rule == "client":
                seq = frame["seq"]
            elif seq_rule == "server":
                seq = server_seq[0]
                server_seq[0] += 1
            else:
                seq = int(seq_rule)
            cmd = int(str(s.get("cmd", CONNECT_CMD)), 0)
            body = bytes.fromhex(s.get("body", "00" * 12))
            footer = bytes.fromhex(s.get("footer", CONNECT_FOOTER.hex()))
            out.append(cipher.seal(header(cmd, seq, body, footer)))
    return out


def run(
    directory,
    host,
    port,
    player,
    mode,
    control_stdin=False,
    activity="queue",
    reply_plan=None,
    reply_after=0,
    burst=DEFAULT_BURST,
    plan_name=None,
):
    directory.mkdir(parents=True, exist_ok=True)
    state_path = directory / "state.json"
    stop = threading.Event()
    if control_stdin:
        _stop_when_parent_closes_stdin(stop)

    state = {
        "id": directory.name,
        "pid": os.getpid(),
        "player": player,
        "mode": f"0x{mode:016X}",
        "host": host,
        "port": port,
        "activity": activity,
        "state": "starting",
        "protocol_ready": False,
        "packets_received": 0,
        "bytes_received": 0,
        "client_cipher": None,
        "replies_sent": 0,
        "sweep_size": None,
        "reply_plan": plan_name,
        "client_reacted": False,
        "reaction": None,
        "shapes_seen": [],
        "started_at": time.time(),
        "first_packet_at": None,
        "last_packet_at": None,
    }

    # Load the AES code now: its first use costs ~0.8 s on Windows, which delayed the first replies and
    # looked like a pause of the client in the 6b6a7071 capture.
    gamecrypto.ZERO.tag(header(CONNECT_CMD, 0))

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
        with (
            (directory / "packets.jsonl").open("a", encoding="utf-8", buffering=1) as plog,
            (directory / "replies.jsonl").open("a", encoding="utf-8", buffering=1) as rlog,
        ):
            bursts = _serve(sock, stop, state, state_path, plog, rlog, reply_plan, reply_after, burst)

    state.update(state="stopped", stopped_at=time.time())
    _note_quiet(state)
    _note_early_end(state, bursts)
    write_state(state_path, state)
    return 0


def _serve(sock, stop, state, state_path, plog, rlog, reply_plan, reply_after, burst):
    baseline_shape = ("connect", CONNECT_CMD, CONNECT_FOOTER.hex(), False)
    seen_shapes, peers = set(), set()
    client: GameCipher | None = None
    sweep: Sweep | None = None
    server_seq = [0]
    recent: list[dict] = []  # candidates sent since the previous inbound packet
    bursts: deque[list[dict]] = deque(maxlen=3)  # the last few of those, newest last
    previous_at = None

    def log_reply(entry):
        rlog.write(json.dumps({"time": time.time(), **entry}) + "\n")

    while not stop.is_set():
        try:
            data, peer = sock.recvfrom(65535)
        except TimeoutError:
            if not state.get("client_went_quiet"):
                _note_quiet(state, recent)
                if state.get("client_went_quiet"):
                    write_state(state_path, state)
            continue
        now = time.time()
        if previous_at is not None and now - previous_at > 2 * BASELINE_INTERVAL and state["replies_sent"]:
            # The client sends every ~0.26 s. A longer gap right after our replies means it was busy with
            # one of them (the 6b6a7071 capture paused 0.74 s, then gave up early).
            state.setdefault("client_pauses", []).append(
                {
                    "after_packet": state["packets_received"],
                    "gap": round(now - previous_at, 3),
                    "candidates_just_before": [c for b in bursts for c in b],
                }
            )
        previous_at = now
        if state["first_packet_at"] is None:
            state["first_packet_at"] = now
        state["packets_received"] += 1
        state["bytes_received"] += len(data)
        state["last_packet_at"] = now

        if client is None and state["client_cipher"] is None:
            client = gamecrypto.identify(data)
            # Unknown key: the handoff keys are not used as-is. Say so, and still answer with every
            # candidate so the run is not wasted.
            state["client_cipher"] = client.name if client else "unknown"
            if reply_plan is None:
                ciphers = gamecrypto.peer_candidates(client) if client else gamecrypto.candidate_ciphers()
                sweep = Sweep(ciphers)
                state["sweep_size"] = len(sweep)
        verified = client.verify(data) if client else False
        plog.write(
            json.dumps(
                {
                    "time": now,
                    "peer": list(peer),
                    "bytes": len(data),
                    "hex": data.hex(),
                    "verified": verified,
                }
            )
            + "\n"
        )

        shape = frame_shape(data)
        new_peer = bool(peers) and peer not in peers
        peers.add(peer)
        if shape not in seen_shapes or new_peer:
            seen_shapes.add(shape)
            state["shapes_seen"] = [list(s) for s in seen_shapes]
            if (shape != baseline_shape or new_peer) and not state["client_reacted"]:
                # A kind of packet the no-reply baseline never has: the client reacted to a reply.
                state["client_reacted"] = True
                state["reaction"] = {
                    "packet": state["packets_received"],
                    "shape": list(shape),
                    "peer": list(peer),
                    "hex": data.hex(),
                    "verified_with_client_cipher": verified,
                    "candidates_just_before": recent[-burst:],
                    "replies_sent_before": state["replies_sent"],
                }
                log_reply({"event": "client_reacted", **state["reaction"]})

        frame = parse_frame(data)
        if frame is not None and state["packets_received"] > reply_after:
            recent = []
            bursts.append(recent)
            if reply_plan is not None:
                steps = plan_steps(reply_plan, state["packets_received"] - 1 - reply_after)
                for step, packet in zip(
                    steps, plan_replies(frame, data, steps, client, server_seq), strict=True
                ):
                    meta = {"plan": step, "in_reply_to_seq": frame["seq"]}
                    if _send(sock, packet, peer, state, log_reply, meta):
                        recent.append(step.get("sealed", step))
            elif sweep is not None:
                for _ in range(burst):
                    item = sweep.next(frame["seq"])
                    if item is None:
                        break
                    index, cipher, cmd, ack, packet = item
                    meta = {"i": index, "cipher": cipher.name, "cmd": f"0x{cmd:08X}", "ack": ack}
                    if _send(sock, packet, peer, state, log_reply, {**meta, "in_reply_to_seq": frame["seq"]}):
                        recent.append(meta)
        write_state(state_path, state)
    return list(bursts)


def _send(sock, packet, peer, state, log_reply, meta) -> bool:
    try:
        sock.sendto(packet, peer)
    except OSError as error:
        log_reply({"event": "send_error", "error": str(error), **meta})
        return False
    state["replies_sent"] += 1
    log_reply({"event": "sent", "to": list(peer), "hex": packet.hex(), **meta})
    return True


def _note_quiet(state, recent=None):
    """The client normally sends ~39 connect packets ~0.26 s apart. Stopping well short of that while
    we were answering is a reaction too (it accepted something, or was told to go away)."""
    last = state.get("last_packet_at")
    if not last or not state["replies_sent"] or state.get("client_went_quiet"):
        return
    silent_for = time.time() - last
    if state["packets_received"] < BASELINE_PACKETS - 5 and silent_for > 8 * BASELINE_INTERVAL:
        state["client_went_quiet"] = {
            "after_packets": state["packets_received"],
            "silent_for": round(silent_for, 2),
            "candidates_just_before": recent,
        }


def _note_early_end(state, bursts):
    """The server stops this process when the game drops its lobby connection, which the game does when
    it gives up on the game server. Stopping well short of its usual ~39 packets means it gave up early,
    most likely because of something it accepted in the last replies."""
    if state["replies_sent"] and 0 < state["packets_received"] < BASELINE_PACKETS - 5:
        state["client_ended_early"] = {
            "after_packets": state["packets_received"],
            "candidates_just_before": [c for b in bursts for c in b],
        }


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--player", required=True)
    parser.add_argument("--mode", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--control-stdin", action="store_true")
    parser.add_argument("--activity", choices=("queue", "practice"), default="queue")
    parser.add_argument("--reply-plan", type=Path, default=None, help="JSON replies, not the sweep")
    parser.add_argument("--reply-after", type=int, default=0, help="start replying after this many packets")
    parser.add_argument("--burst", type=int, default=DEFAULT_BURST, help="candidates per inbound packet")
    args = parser.parse_args()
    plan_path = args.reply_plan or (
        Path(os.environ["OW174_REPLY_PLAN"]) if os.environ.get("OW174_REPLY_PLAN") else None
    )
    plan = json.loads(plan_path.read_text(encoding="utf-8")) if plan_path else None
    return run(
        args.directory,
        args.host,
        args.port,
        args.player,
        args.mode,
        args.control_stdin,
        args.activity,
        plan,
        args.reply_after,
        args.burst,
        str(plan_path) if plan_path else None,
    )


if __name__ == "__main__":
    raise SystemExit(main())
