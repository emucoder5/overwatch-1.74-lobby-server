"""Scripted replies for protocol experiments, such as what the server sends after a Practice Range request.

Start the server with `--experiment practice` (experiments/practice.json) or `--experiment <file>`.
A plan is a JSON file:

    {
      "description": "what this plan tests",
      "on": ["practice"],              which requests start it: "practice" (24000), "queue" (44100)
      "watch": 30,                     seconds to wait for UDP packets after the last step
      "steps": [
        {"send": ["074DAD18", 20600], "after": 0.5, "value": {"+0x80": {"+0x2C": "$port_host"}}},
        ...
      ]
    }

Each step starts from the message's empty value (all zeros) and overrides the fields in "value". A
field that the message does not have is an error, so typos show up at once. "after" is the delay in
seconds since the previous step. A step with "unless_connected": true is skipped once the game has
sent the instance a UDP packet. While a run is going, the game's repeats of the same request are
counted but do not restart it.

String values that start with "$" are replaced:

    $ip_host    the instance IPv4 address as a number (127.0.0.1 -> 0x7F000001)
    $ip_net     the same address with its bytes swapped (127.0.0.1 -> 0x0100007F)
    $port_host  the instance UDP port
    $port_net   the port with its two bytes swapped
    $token      a random 64-bit number, the same for every step of one run

The plan is read again for every request, so it can be edited while the server runs. The results go
to the log: each step sent, then whether the game sent UDP packets to the instance.
"""

import copy
import json
import logging
import random
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from ow174.paths import ROOT

if TYPE_CHECKING:
    from ow174.jam.codec import Schemas
    from ow174.lobby.session import Session
    from ow174.matches.runtime import MatchInstance

EXPERIMENTS_DIR = ROOT / "experiments"
ACTIVITIES = ("practice", "queue")
MAX_DELAY = 600.0


class PlanError(ValueError):
    pass


@dataclass
class Step:
    crc: int
    msg_id: int
    value: dict
    after: float = 0.0
    unless_connected: bool = False


@dataclass
class Plan:
    name: str
    description: str
    on: tuple[str, ...]
    watch: float
    steps: list[Step] = field(default_factory=list)


def resolve_plan_path(text: str) -> Path:
    """A bare name such as "practice" means experiments/practice.json; anything else is a path."""
    path = Path(text)
    if path.suffix == "" and path.parent == Path("."):
        path = EXPERIMENTS_DIR / f"{text}.json"
    return path


def _delay(value, what: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= MAX_DELAY:
        raise PlanError(f"{what} must be a number of seconds from 0 to {MAX_DELAY:g}")
    return float(value)


def load_plan(path: Path, schemas: "Schemas") -> Plan:
    """Read and check a plan. Every step is test-encoded, so a broken plan fails before it is used."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise PlanError(f"Cannot read {path}: {error}") from error
    if not isinstance(data, dict) or not isinstance(data.get("steps"), list) or not data["steps"]:
        raise PlanError(f'{path}: a plan needs a non-empty "steps" list')
    on = tuple(data.get("on", ["practice"]))
    if not on or any(activity not in ACTIVITIES for activity in on):
        raise PlanError(f'{path}: "on" must list some of {ACTIVITIES}')
    plan = Plan(
        name=Path(path).stem,
        description=str(data.get("description", "")),
        on=on,
        watch=_delay(data.get("watch", 30), "watch"),
    )
    sample = placeholders("127.0.0.1", 3730, 0x0123456789ABCDEF)
    for number, raw in enumerate(data["steps"], start=1):
        where = f"{path} step {number}"
        if not isinstance(raw, dict) or not isinstance(raw.get("send"), list) or len(raw["send"]) != 2:
            raise PlanError(f'{where}: "send" must be ["<crc hex>", <message id>]')
        try:
            crc, msg_id = int(str(raw["send"][0]), 16), int(raw["send"][1])
        except (TypeError, ValueError) as error:
            raise PlanError(f'{where}: bad "send": {error}') from error
        try:
            schemas.empty(crc, msg_id)
        except KeyError:
            raise PlanError(f"{where}: no schema for {crc:08X}/{msg_id}") from None
        value = raw.get("value", {})
        if not isinstance(value, dict):
            raise PlanError(f'{where}: "value" must be an object')
        step = Step(
            crc,
            msg_id,
            value,
            _delay(raw.get("after", 0), f"{where}: after"),
            bool(raw.get("unless_connected")),
        )
        try:
            build_value(schemas, step, sample)
        except (KeyError, TypeError, ValueError) as error:
            raise PlanError(f"{where}: {error}") from error
        plan.steps.append(step)
    return plan


def placeholders(host: str, port: int, token: int) -> dict[str, int]:
    packed = socket.inet_aton(host)
    return {
        "$ip_host": int.from_bytes(packed, "big"),
        "$ip_net": int.from_bytes(packed, "little"),
        "$port_host": port,
        "$port_net": int.from_bytes(port.to_bytes(2, "big"), "little"),
        "$token": token,
    }


def _merge(base, override, names: dict[str, int], path: str):
    """Override fields of an empty message value. Unknown fields and placeholders are errors."""
    if isinstance(override, str) and override.startswith("$"):
        if override not in names:
            raise ValueError(f"{path}: unknown placeholder {override} (known: {', '.join(names)})")
        return names[override]
    if isinstance(override, dict):
        if base is None:  # an element of an array the plan gives in full
            return {key: _merge(None, value, names, f"{path}{key}.") for key, value in override.items()}
        if not isinstance(base, dict):
            raise TypeError(f"{path}: this field is not a struct")
        merged = dict(base)
        for key, value in override.items():
            if key not in base:
                raise KeyError(f"{path}{key}: the message has no such field (fields: {', '.join(base)})")
            merged[key] = _merge(base[key], value, names, f"{path}{key}.")
        return merged
    if isinstance(override, list):
        return [_merge(None, item, names, f"{path}[{index}].") for index, item in enumerate(override)]
    return override


def build_value(schemas: "Schemas", step: Step, names: dict[str, int]) -> dict:
    value = _merge(schemas.empty(step.crc, step.msg_id), copy.deepcopy(step.value), names, "")
    schemas.encode(step.crc, step.msg_id, value)  # raises on a value the message cannot carry
    return value


def packets_received(instance: "MatchInstance") -> int:
    try:
        state = json.loads((instance.directory / "state.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    return int(state.get("packets_received", 0))


class ExperimentRunner:
    """Runs a plan in the background per client; repeated requests during a run are only counted."""

    def __init__(self, plan_path: Path, schemas: "Schemas") -> None:
        self.plan_path = plan_path
        self.schemas = schemas
        self._runs: dict[int, int] = {}  # connection id -> generation of its current run
        self._repeats: dict[int, int] = {}  # connection id -> requests ignored while its run is going
        self._lock = threading.Lock()

    def check(self) -> Plan:
        """Load the plan once at startup so a broken file is reported right away."""
        return load_plan(self.plan_path, self.schemas)

    def start(self, session: "Session", instance: "MatchInstance", activity: str) -> bool:
        try:
            plan = load_plan(self.plan_path, self.schemas)
        except PlanError as error:
            session.log(f"[exp] Plan not run: {error}", logging.WARNING)
            return False
        if activity not in plan.on:
            return False
        with self._lock:
            # The game repeats its request while it waits. Restarting the plan each time would keep it
            # from ever reaching the later steps, so repeats are counted and ignored until the run ends.
            if session.conn_id in self._repeats:
                self._repeats[session.conn_id] += 1
                if self._repeats[session.conn_id] == 1:
                    session.log("[exp] The game repeated its request; ignoring repeats until this run ends")
                return False
            generation = self._runs.get(session.conn_id, 0) + 1
            self._runs[session.conn_id] = generation
            self._repeats[session.conn_id] = 0
        threading.Thread(
            target=self._run,
            args=(session, instance, plan, generation),
            daemon=True,
            name=f"experiment-{session.conn_id}",
        ).start()
        return True

    def _current(self, session: "Session", generation: int) -> bool:
        with self._lock:
            return self._runs.get(session.conn_id) == generation

    def _run(self, session: "Session", instance: "MatchInstance", plan: Plan, generation: int) -> None:
        token = random.getrandbits(64)
        names = placeholders("127.0.0.1", instance.port, token)
        session.log(
            f"[exp] Plan '{plan.name}': {len(plan.steps)} steps, instance UDP 127.0.0.1:{instance.port}, "
            f"token 0x{token:016X}. {plan.description}"
        )
        try:
            for number, step in enumerate(plan.steps, start=1):
                time.sleep(step.after)
                if not self._current(session, generation):
                    session.log("[exp] Stopped: a newer request replaced this run")
                    return
                label = f"step {number}/{len(plan.steps)} {step.crc:08X}/{step.msg_id}"
                if step.unless_connected and packets_received(instance):
                    session.log(f"[exp] {label} skipped: the game is already sending UDP packets")
                    continue
                value = build_value(self.schemas, step, names)
                sent = session.send(step.crc, step.msg_id, value)
                session.log(f"[exp] {label} {'sent' if sent else 'NOT sent (protocol not announced)'}")
            self._watch(session, instance, plan, generation)
        except OSError:
            session.log("[exp] Stopped: the client disconnected")
        finally:
            with self._lock:
                if self._runs.get(session.conn_id) == generation:
                    self._repeats.pop(session.conn_id, None)

    def _watch(self, session: "Session", instance: "MatchInstance", plan: Plan, generation: int) -> None:
        deadline = time.monotonic() + plan.watch
        while time.monotonic() < deadline and self._current(session, generation):
            if packets_received(instance):
                break
            time.sleep(0.25)
        count = packets_received(instance)
        with self._lock:
            repeats = self._repeats.get(session.conn_id, 0)
        if repeats:
            session.log(f"[exp] The game repeated its request {repeats} time(s) during this run")
        if count:
            session.log(
                f"[exp] RESULT: the game sent {count} UDP packet(s) to the instance. "
                f"They are in {instance.directory / 'packets.jsonl'}"
            )
        else:
            session.log(f"[exp] RESULT: no UDP packets reached the instance within {plan.watch:g}s")
