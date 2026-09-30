"""The game-server packet seal of the 1.74 client: AES-256-GCM with a 12-byte tag.

Found from the capture in logs/matches/713ac6d1fd11486e932ac7ed03e46d59 (all 39 connect packets
verify) and the client image (logs/overwatch_image.zip, base 0x7FF632310000):

    packet  = tag[12] || header...
    tag     = first 12 bytes of the AES-256-GCM tag, empty plaintext, AAD = packet[12:]
    nonce   = prefix[8] || seq (u32 LE, the same value as packet[16:20])
    key     = 32 bytes

RVAs in the image:
    0x03FAD50  AES-GCM cipher constructor. Copies a 40-byte {key[32], prefix[8]} block and stores it
               masked (0x03FA810 unmasks it for every packet).
    0x03FB2E0  seal (vtable 0x25F5BE0), 0x03FB740 open (vtable 0x25F5BD8). Both build the nonce as
               {prefix (qword), seq (dword)} and call SymCrypt GCM with cbNonce = 12.
    0x03FBC60  cipher factory: type 2 = no cipher, 0 = raw key, >=3 = the masked AES-GCM above.
    0x03F89E0  game connection constructor: builds TWO ciphers from one 80-byte key block,
               block[0x00:0x28] -> conn+0x10 and block[0x28:0x50] -> conn+0x18. One seals what the
               client sends, the other opens what it receives.
    0x24D2500 / 0x24D2770  SymCrypt GcmEncrypt / GcmDecrypt; 0x24D2BB0 GcmInit (checks cbNonce == 12).

The 20600 handoff carries two u8[32] fields (+0x80+0xAE and +0x80+0xCE). Every plan so far left them
zero, and the client then sealed with an all-zero key and an all-zero prefix. That is consistent with
the two keys coming straight from those fields; experiments/practice_keys.json fills them with the
PROBE values below so a capture shows which field (and which u64, if any, as prefix) seals which
direction.

    py -m ow174.matches.gamecrypto logs/matches/<id>     report which cipher the client's packets verify with
"""

import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

TAG_LEN = 12
SEQ_OFFSET = 16  # packet[16:20] is the sequence number, and the last 4 bytes of the nonce


# Known values the practice_keys plan writes into the 20600 handoff, so the responder can tell which
# of them the client uses. Distinct and easy to spot in a hex dump.
PROBE_KEY_AE = bytes(range(0xA0, 0xC0))  # +0x80 +0xAE
PROBE_KEY_CE = bytes(range(0xC0, 0xE0))  # +0x80 +0xCE
PROBE_U64 = {
    "id_lo": 0x1111111111111111,  # +0x80 +0x00 +0x00
    "id_hi": 0x2222222222222222,  # +0x80 +0x00 +0x08
    "u64_10": 0x3333333333333333,  # +0x80 +0x10
    "u64_18": 0x4444444444444444,  # +0x80 +0x18
    "u64_20": 0x5555555555555555,  # +0x80 +0x20
}


@dataclass(frozen=True)
class GameCipher:
    """One direction's key and 8-byte nonce prefix."""

    key: bytes
    prefix: bytes = bytes(8)
    name: str = ""

    def __post_init__(self):
        if len(self.key) != 32 or len(self.prefix) != 8:
            raise ValueError("a game cipher needs a 32-byte key and an 8-byte prefix")

    def nonce(self, seq: int) -> bytes:
        return self.prefix + struct.pack("<I", seq & 0xFFFFFFFF)

    def tag(self, header: bytes) -> bytes:
        """The 12-byte tag for a packet whose bytes after the tag are `header` (all authenticated)."""
        if len(header) < SEQ_OFFSET - TAG_LEN + 4:
            raise ValueError("header too short to hold the sequence number")
        # Imported here, not at the top: the server imports this module before ensure_requirements()
        # has installed the package on a fresh setup.
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        (seq,) = struct.unpack_from("<I", header, SEQ_OFFSET - TAG_LEN)
        return AESGCM(self.key).encrypt(self.nonce(seq), b"", header)[:TAG_LEN]

    def seal(self, header: bytes) -> bytes:
        return self.tag(header) + header

    def verify(self, packet: bytes) -> bool:
        if len(packet) < SEQ_OFFSET + 4:
            return False
        return self.tag(packet[TAG_LEN:]) == packet[:TAG_LEN]


ZERO = GameCipher(bytes(32), bytes(8), "zero")


def _prefixes() -> dict[str, bytes]:
    out = {"zero": bytes(8)}
    for name, value in PROBE_U64.items():
        out[f"{name}_le"] = struct.pack("<Q", value)
        out[f"{name}_be"] = struct.pack(">Q", value)
    return out


def candidate_ciphers() -> list[GameCipher]:
    """Every (key, prefix) pair the client might seal with, zero first (the result of every run so far)."""
    keys = {"zero": bytes(32), "ae": PROBE_KEY_AE, "ce": PROBE_KEY_CE}
    return [
        GameCipher(key, prefix, f"key_{kname}/prefix_{pname}")
        for kname, key in keys.items()
        for pname, prefix in _prefixes().items()
    ]


def identify(packet: bytes, candidates: list[GameCipher] | None = None) -> GameCipher | None:
    """The candidate whose tag matches this client packet, or None."""
    for cipher in candidates if candidates is not None else candidate_ciphers():
        if cipher.verify(packet):
            return cipher
    return None


def peer_candidates(client: GameCipher) -> list[GameCipher]:
    """Plausible ciphers for the other direction, most likely first, once the client's is known.

    The connection holds two {key, prefix} blocks. If the client sends with one probe key, the server
    most likely sends with the other; the prefix is either the same kind or another handoff u64.
    With the zero handoff both keys are zero, so only the prefix can differ.
    """
    kname = client.name.split("/")[0].removeprefix("key_")
    other = {"ae": PROBE_KEY_CE, "ce": PROBE_KEY_AE}.get(kname, client.key)
    keys = [other] if other == client.key else [other, client.key]
    prefixes = [client.prefix, *[p for p in _prefixes().values() if p != client.prefix]]
    # Direction bits some protocols put in the nonce, applied to the client's prefix.
    for flip in (0x80, 0x01):
        prefixes.append(bytes([client.prefix[0] ^ flip]) + client.prefix[1:])
        prefixes.append(client.prefix[:7] + bytes([client.prefix[7] ^ flip]))
    out, seen = [], set()
    for key in keys:
        for prefix in prefixes:
            if (key, prefix) in seen:
                continue
            seen.add((key, prefix))
            label = "ae" if key == PROBE_KEY_AE else "ce" if key == PROBE_KEY_CE else "zero"
            out.append(GameCipher(key, prefix, f"key_{label}/prefix_{prefix.hex()}"))
    return out


def report(directory: Path) -> int:
    """Print which candidate cipher verifies each packet in a capture folder."""
    lines = (directory / "packets.jsonl").read_text(encoding="utf-8").splitlines()
    candidates = candidate_ciphers()
    counts: dict[str, int] = {}
    for line in lines:
        packet = bytes.fromhex(json.loads(line)["hex"])
        cipher = identify(packet, candidates)
        name = cipher.name if cipher else "NONE (key or nonce is not one of the candidates)"
        counts[name] = counts.get(name, 0) + 1
    print(f"{len(lines)} packet(s) in {directory}")
    for name, count in counts.items():
        print(f"  {count:4d}  {name}")
    return 0 if counts and not any(name.startswith("NONE") for name in counts) else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(report(Path(sys.argv[1])))
