"""The game-server packet seal (AES-256-GCM) and the sealed-reply responder."""

import json
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ow174.matches import gamecrypto
from ow174.matches.gamecrypto import PROBE_KEY_AE, PROBE_KEY_CE, PROBE_U64, ZERO, GameCipher
from ow174.matches.responder import CONNECT_CMD, Sweep, _note_early_end, header, plan_replies, plan_steps

ROOT = Path(__file__).resolve().parents[1]

# Real connect packets from the 1.74 client (logs/matches/713ac6d1fd11486e932ac7ed03e46d59), sent after
# a 20600 handoff whose key fields were all zero.
CAPTURED = [
    "66e4ab75ab8b83a2bb00ee01100000f00000000000000000000000000000000001ad",
    "df4642542ea3f24b5196f8c6100000f00100000000000000000000000000000001ad",
    "0b3cdfd85e54d75a6076751c100000f00200000000000000000000000000000001ad",
    "a9c7f0059eef36bf792af30b100000f02600000000000000000000000000000001ad",
]
# From capture 6b6a7071901c429b97067ffe68a541d1 (practice_keys handoff): sealed with the +0xAE key and
# the +0x18 u64 as the nonce prefix.
CAPTURED_KEYS = "2520a43edcbdc95f7f1b423d100000f00000000000000000000000000000000001ad"


def connect(cipher: GameCipher, seq: int) -> bytes:
    return cipher.seal(header(CONNECT_CMD, seq))


class SealTests(unittest.TestCase):
    def test_captured_connect_packets_verify_with_the_zero_key(self):
        for text in CAPTURED:
            with self.subTest(text[:8]):
                self.assertTrue(ZERO.verify(bytes.fromhex(text)))

    def test_sealing_reproduces_the_captured_packets(self):
        for text in CAPTURED:
            packet = bytes.fromhex(text)
            self.assertEqual(ZERO.seal(packet[12:]), packet)

    def test_any_changed_byte_breaks_the_tag(self):
        packet = bytearray.fromhex(CAPTURED[1])
        for offset in (0, 11, 12, 16, 20, 33):
            broken = bytearray(packet)
            broken[offset] ^= 1
            self.assertFalse(ZERO.verify(bytes(broken)), offset)

    def test_the_nonce_is_prefix_then_seq(self):
        cipher = GameCipher(bytes(32), bytes(range(8)))
        self.assertEqual(cipher.nonce(0x01020304), bytes(range(8)) + b"\x04\x03\x02\x01")

    def test_identify_finds_the_probe_key_and_prefix(self):
        prefix = struct.pack("<Q", PROBE_U64["u64_18"])
        packet = connect(GameCipher(PROBE_KEY_CE, prefix), 3)
        found = gamecrypto.identify(packet)
        self.assertEqual(found.name, "key_ce/prefix_u64_18_le")
        self.assertEqual(gamecrypto.identify(bytes.fromhex(CAPTURED[0])).name, "key_zero/prefix_zero")
        self.assertIsNone(gamecrypto.identify(bytes(34)))

    def test_the_keyed_handoff_capture_uses_key_ae_and_prefix_u64_18(self):
        found = gamecrypto.identify(bytes.fromhex(CAPTURED_KEYS))
        self.assertEqual(found.name, "key_ae/prefix_u64_18_le")

    def test_the_other_probe_key_is_tried_first_for_replies(self):
        client = GameCipher(PROBE_KEY_AE, bytes(8), "key_ae/prefix_zero")
        peers = gamecrypto.peer_candidates(client)
        self.assertEqual((peers[0].key, peers[0].prefix), (PROBE_KEY_CE, bytes(8)))
        self.assertIn((PROBE_KEY_AE, bytes(8)), [(p.key, p.prefix) for p in peers])
        self.assertEqual(len({(p.key, p.prefix) for p in peers}), len(peers))

    def test_report_reads_a_capture_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            lines = [json.dumps({"hex": text}) for text in CAPTURED]
            (path / "packets.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertEqual(gamecrypto.report(path), 0)


class SweepTests(unittest.TestCase):
    def test_candidates_are_sealed_and_counted_per_cipher(self):
        ciphers = gamecrypto.peer_candidates(ZERO)
        sweep = Sweep(ciphers)
        first = [sweep.next(client_seq=9) for _ in range(12)]
        self.assertEqual({hex(item[2]) for item in first[:6]}, {hex(CONNECT_CMD)})
        by_name = {c.name: c for c in ciphers}
        seen = {}
        for _index, cipher, _cmd, ack, packet in first:
            self.assertTrue(by_name[cipher.name].verify(packet))
            seq = struct.unpack_from("<I", packet, 16)[0]
            self.assertEqual(seq, seen.get(cipher.name, -1) + 1)
            seen[cipher.name] = seq
            self.assertEqual(packet[20:24], struct.pack("<I", 9) if ack else bytes(4))
        self.assertGreater(len(sweep), 256)

    def test_a_sealed_plan_step_verifies(self):
        client = GameCipher(PROBE_KEY_AE, bytes(8), "c")
        frame = {"seq": 5}
        step = {"sealed": {"cmd": "0xF0000011", "seq": "client", "key": PROBE_KEY_CE.hex()}}
        (packet,) = plan_replies(frame, b"", [step], client, [0])
        self.assertTrue(GameCipher(PROBE_KEY_CE, bytes(8)).verify(packet))
        self.assertEqual(struct.unpack_from("<II", packet, 12), (0xF0000011, 5))


class PlanTests(unittest.TestCase):
    def test_a_list_plan_repeats_and_a_per_packet_plan_steps_through(self):
        self.assertEqual(plan_steps([{"hex": "00"}], 7), [{"hex": "00"}])
        plan = {"per_packet": [[{"hex": "01"}], [{"hex": "02"}]], "then": [{"hex": "03"}]}
        self.assertEqual([plan_steps(plan, n)[0]["hex"] for n in range(4)], ["01", "02", "03", "03"])
        self.assertEqual(plan_steps({"per_packet": []}, 0), [])

    def test_named_keys_and_prefixes(self):
        client = GameCipher(PROBE_KEY_AE, struct.pack("<Q", PROBE_U64["u64_18"]))
        step = {"sealed": {"key": "ce", "prefix": "client", "cmd": "0xF00000BB"}}
        (packet,) = plan_replies({"seq": 0}, b"", [step], client, [0])
        self.assertTrue(GameCipher(PROBE_KEY_CE, client.prefix).verify(packet))
        step = {"sealed": {"key": "zero", "prefix": "u64_20"}}
        (packet,) = plan_replies({"seq": 0}, b"", [step], client, [0])
        self.assertTrue(GameCipher(bytes(32), struct.pack("<Q", PROBE_U64["u64_20"])).verify(packet))

    def test_the_shipped_bisect_plan_is_one_ce_reply_per_packet(self):
        plan = json.loads((ROOT / "experiments/replies/bisect_a9_c8.json").read_text(encoding="utf-8"))
        cmds = [steps[0]["sealed"]["cmd"] for steps in plan["per_packet"]]
        self.assertEqual(cmds[0], "0xF00000B9")
        self.assertEqual(sorted(int(c, 16) for c in cmds), list(range(0xF00000A9, 0xF00000C9)))
        self.assertTrue(
            all(len(steps) == 1 and steps[0]["sealed"]["key"] == "ce" for steps in plan["per_packet"])
        )

    def test_the_shipped_silent_and_echo_plans(self):
        silent = json.loads((ROOT / "experiments/replies/silent.json").read_text(encoding="utf-8"))
        self.assertEqual([plan_steps(silent, n) for n in range(40)], [[]] * 40)
        echo = json.loads((ROOT / "experiments/replies/echo_ce.json").read_text(encoding="utf-8"))
        client = GameCipher(PROBE_KEY_AE, struct.pack("<Q", PROBE_U64["u64_18"]))
        for seq in (0, 7):
            (packet,) = plan_replies({"seq": seq}, b"", plan_steps(echo, seq), client, [0])
            self.assertTrue(GameCipher(PROBE_KEY_CE, client.prefix).verify(packet))
            self.assertEqual(packet[12:], header(CONNECT_CMD, seq))

    def test_early_end_is_recorded_with_the_last_replies(self):
        state = {"replies_sent": 5, "packets_received": 31}
        _note_early_end(state, [[{"cmd": "a"}], [{"cmd": "b"}]])
        self.assertEqual(state["client_ended_early"]["candidates_just_before"], [{"cmd": "a"}, {"cmd": "b"}])
        state = {"replies_sent": 5, "packets_received": 39}
        _note_early_end(state, [])
        self.assertNotIn("client_ended_early", state)


class ResponderProcessTests(unittest.TestCase):
    """Run the responder as runtime.py does, against a simulated client that only reacts to one
    correctly sealed command, and check the reaction is detected and attributed."""

    def test_reaction_to_a_correctly_sealed_reply_is_caught(self):
        client_cipher = GameCipher(PROBE_KEY_AE, bytes(8))
        server_cipher = GameCipher(PROBE_KEY_CE, bytes(8))
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp) / "m"
            process = subprocess.Popen(
                [sys.executable, "-B", "-m", "ow174.matches.responder", "--directory", str(directory),
                 "--player", "T", "--mode", "0", "--port", "0", "--control-stdin", "--burst", "48"],
                cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )  # fmt: skip
            try:
                state_path = directory / "state.json"
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if state_path.is_file() and json.loads(state_path.read_text())["state"] == "listening":
                        break
                    time.sleep(0.02)
                port = json.loads(state_path.read_text())["port"]
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.05)
                accepted = False
                for seq in range(20):
                    body = header(0xF0000099, seq, b"\x07" * 12) if accepted else header(CONNECT_CMD, seq)
                    sock.sendto(client_cipher.seal(body), ("127.0.0.1", port))
                    end = time.monotonic() + 0.1
                    while time.monotonic() < end:
                        try:
                            data, _ = sock.recvfrom(2048)
                        except TimeoutError:
                            continue
                        cmd = struct.unpack_from("<I", data, 12)[0]
                        if server_cipher.verify(data) and cmd == 0xF0000011:
                            accepted = True
                    if accepted and seq > 3:
                        break
                sock.close()
                time.sleep(0.3)
            finally:
                process.stdin.close()
                process.wait(timeout=10)
            state = json.loads(state_path.read_text())
        self.assertEqual(state["client_cipher"], "key_ae/prefix_zero")
        self.assertTrue(state["client_reacted"])
        just_before = state["reaction"]["candidates_just_before"]
        self.assertIn(
            {"cipher": "key_ce/prefix_0000000000000000", "cmd": "0xF0000011"},
            [{"cipher": c["cipher"], "cmd": c["cmd"]} for c in just_before],
        )

    def test_a_pause_after_a_scripted_reply_is_attributed(self):
        client_cipher = GameCipher(PROBE_KEY_AE, bytes(8))
        server_cipher = GameCipher(PROBE_KEY_CE, bytes(8))
        cmds = [0xF00000B9, 0xF00000BA, 0xF00000BB, 0xF00000BC, 0xF00000BD]
        with tempfile.TemporaryDirectory() as temp:
            plan_path = Path(temp) / "plan.json"
            steps = [[{"sealed": {"key": "ce", "prefix": "client", "cmd": hex(c)}}] for c in cmds]
            plan_path.write_text(json.dumps({"per_packet": steps}), encoding="utf-8")
            directory = Path(temp) / "m"
            process = subprocess.Popen(
                [sys.executable, "-B", "-m", "ow174.matches.responder", "--directory", str(directory),
                 "--player", "T", "--mode", "0", "--port", "0", "--control-stdin",
                 "--reply-plan", str(plan_path)],
                cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )  # fmt: skip
            try:
                state_path = directory / "state.json"
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if state_path.is_file() and json.loads(state_path.read_text())["state"] == "listening":
                        break
                    time.sleep(0.02)
                port = json.loads(state_path.read_text())["port"]
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.3)
                for seq in range(len(cmds)):
                    sock.sendto(client_cipher.seal(header(CONNECT_CMD, seq)), ("127.0.0.1", port))
                    data, _ = sock.recvfrom(2048)
                    self.assertTrue(server_cipher.verify(data))
                    # The simulated game is busy for a while after 0xF00000BB, like the real one was.
                    time.sleep(0.8 if struct.unpack_from("<I", data, 12)[0] == 0xF00000BB else 0.05)
                sock.close()
                time.sleep(0.3)
            finally:
                process.stdin.close()
                process.wait(timeout=10)
            state = json.loads(state_path.read_text())
        (pause,) = state["client_pauses"]
        self.assertEqual(pause["candidates_just_before"][-1]["cmd"], "0xf00000bb")
        self.assertEqual(state["client_ended_early"]["after_packets"], len(cmds))
        self.assertEqual(state["reply_plan"], str(plan_path))


if __name__ == "__main__":
    unittest.main()
