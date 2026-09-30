import json
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ow174.accounts.profile import Profile
from ow174.jam.codec import Schemas
from ow174.lobby.experiments import (
    ExperimentRunner,
    PlanError,
    build_value,
    load_plan,
    placeholders,
    resolve_plan_path,
)
from ow174.lobby.handlers import build_router
from ow174.lobby.session import Session
from ow174.matches import gamecrypto
from ow174.matches.runtime import MatchManager

CUSTOM = 0xA6E53896
HANDOFF = 0x074DAD18
PRACTICE_BODY = bytes.fromhex("020004000000")
SHIPPED_PLANS = (
    "practice",
    "practice_net_order",
    "practice_handoff_only",
    "practice_state_sweep",
    "practice_found_sweep",
    "practice_enter",
    "practice_plain_host",
    "practice_keys",
)


def write_plan(directory, steps, **extra):
    path = Path(directory) / "plan.json"
    path.write_text(json.dumps({"steps": steps, **extra}), encoding="utf-8")
    return path


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.schemas = Schemas()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_shipped_plans_load(self):
        for name in SHIPPED_PLANS:
            with self.subTest(name):
                self.assertTrue(load_plan(resolve_plan_path(name), self.schemas).steps)

    def test_placeholders_cover_both_byte_orders(self):
        names = placeholders("127.0.0.1", 0x0E92, 7)
        self.assertEqual(names["$ip_host"], 0x7F000001)
        self.assertEqual(names["$ip_net"], 0x0100007F)
        self.assertEqual(names["$port_host"], 0x0E92)
        self.assertEqual(names["$port_net"], 0x920E)
        self.assertEqual(names["$token"], 7)
        self.assertEqual(names["$host_text"], list(b"127.0.0.1"))

    def test_plain_host_handoff_carries_the_address_as_text(self):
        plan = load_plan(resolve_plan_path("practice_plain_host"), self.schemas)
        handoff = next(step for step in plan.steps if step.msg_id == 20600)
        value = build_value(self.schemas, handoff, placeholders("127.0.0.1", 3730, 7))
        body = self.schemas.encode(HANDOFF, 20600, value)
        decoded = self.schemas.decode(HANDOFF, 20600, body)
        self.assertFalse(decoded["+0x78"])
        self.assertEqual(bytes(decoded["+0x80"]["+0x2E"]).rstrip(b"\0"), b"127.0.0.1")
        self.assertEqual(decoded["+0x80"]["+0x2C"], 3730)

    def test_keys_handoff_carries_the_probe_keys(self):
        plan = load_plan(resolve_plan_path("practice_keys"), self.schemas)
        handoff = next(step for step in plan.steps if step.msg_id == 20600)
        value = build_value(self.schemas, handoff, placeholders("127.0.0.1", 3730, 7))
        decoded = self.schemas.decode(HANDOFF, 20600, self.schemas.encode(HANDOFF, 20600, value))
        self.assertEqual(bytes(decoded["+0x80"]["+0xAE"]), gamecrypto.PROBE_KEY_AE)
        self.assertEqual(bytes(decoded["+0x80"]["+0xCE"]), gamecrypto.PROBE_KEY_CE)
        self.assertEqual(decoded["+0x80"]["+0x18"], gamecrypto.PROBE_U64["u64_18"])
        self.assertEqual(bytes(decoded["+0x80"]["+0x2E"]).rstrip(b"\0"), b"127.0.0.1")

    def test_a_misspelled_field_is_refused(self):
        path = write_plan(self.tmp.name, [{"send": ["074DAD18", 20600], "value": {"+0x80": {"+0x2D": 1}}}])
        with self.assertRaisesRegex(PlanError, r"\+0x2D"):
            load_plan(path, self.schemas)

    def test_an_unknown_placeholder_is_refused(self):
        path = write_plan(self.tmp.name, [{"send": ["074DAD18", 20600], "value": {"+0x78": "$nope"}}])
        with self.assertRaisesRegex(PlanError, r"\$nope"):
            load_plan(path, self.schemas)

    def test_an_unknown_message_is_refused(self):
        path = write_plan(self.tmp.name, [{"send": ["074DAD18", 29999]}])
        with self.assertRaisesRegex(PlanError, "no schema"):
            load_plan(path, self.schemas)

    def test_a_bad_delay_is_refused(self):
        path = write_plan(self.tmp.name, [{"send": ["074DAD18", 20600], "after": -1}])
        with self.assertRaisesRegex(PlanError, "after"):
            load_plan(path, self.schemas)


class PracticeExperimentTests(unittest.TestCase):
    """A Practice Range request runs the plan against a real instance, and reports UDP from the game."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.schemas = Schemas()
        self.matches = MatchManager(Path(self.tmp.name) / "matches", base_port=0)
        self.addCleanup(self.matches.close)
        self.sent = []
        self.logs = []
        self.done = threading.Event()

    def start(self, steps, watch=2):
        path = write_plan(self.tmp.name, steps, watch=watch)
        server = SimpleNamespace(
            matches=self.matches,
            schemas=self.schemas,
            state_lock=threading.RLock(),
            router=build_router(),
            recorder=SimpleNamespace(record=lambda *args: None),
            experiments=ExperimentRunner(path, self.schemas),
        )
        session = Session(server, None, None, 9)
        session.account = SimpleNamespace(name="Alpha", profile=Profile(player_name="Alpha"))
        session.logged_in = True
        session.announce([CUSTOM, HANDOFF, 0x1CFB43CD, 0x21286B49])

        def log(text, level=None):
            self.logs.append(text)
            if "[exp] RESULT" in text:
                self.done.set()

        session.log = log
        session.send = lambda crc, msg_id, value: self.sent.append((crc, msg_id, value)) or True
        self.session = session
        session.dispatch(1, 0, PRACTICE_BODY)
        return self.matches.snapshot()[0]

    def test_the_handoff_points_at_the_instance(self):
        state = self.start(
            [
                {
                    "send": ["074DAD18", 20600],
                    "value": {"+0x78": True, "+0x80": {"+0x28": "$ip_host", "+0x2C": "$port_host"}},
                }
            ],
            watch=0.2,
        )
        self.assertTrue(self.done.wait(5), self.logs)
        [(crc, msg_id, value)] = self.sent
        self.assertEqual((crc, msg_id), (HANDOFF, 20600))
        self.assertEqual(value["+0x80"]["+0x28"], 0x7F000001)
        self.assertEqual(value["+0x80"]["+0x2C"], state["port"])
        self.assertIn("no UDP packets", self.logs[-1])

    def test_repeated_requests_do_not_restart_the_plan(self):
        self.start(
            [
                {"send": ["1CFB43CD", 53000]},
                {"send": ["074DAD18", 20600], "after": 0.3},
            ],
            watch=0.1,
        )
        session = self.session
        for _ in range(3):
            session.dispatch(1, 0, PRACTICE_BODY)
        self.assertTrue(self.done.wait(5), self.logs)
        self.assertEqual([m[1] for m in self.sent], [53000, 20600])
        self.assertTrue(any("repeated its request 3 time" in line for line in self.logs), self.logs)

    def test_udp_from_the_game_is_reported_and_skips_the_idle_reset(self):
        state = self.start(
            [
                {"send": ["074DAD18", 20600], "value": {"+0x80": {"+0x2C": "$port_host"}}},
                {"send": ["1CFB43CD", 53000], "after": 1.0, "unless_connected": True},
            ]
        )
        deadline = time.monotonic() + 5
        while not self.sent and time.monotonic() < deadline:
            time.sleep(0.02)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as game:
            game.sendto(b"hello", ("127.0.0.1", state["port"]))
        self.assertTrue(self.done.wait(5), self.logs)
        self.assertEqual([m[1] for m in self.sent], [20600])
        self.assertTrue(any("skipped" in line for line in self.logs), self.logs)
        self.assertIn("1 UDP packet", self.logs[-1])


if __name__ == "__main__":
    unittest.main()
