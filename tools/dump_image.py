#!/usr/bin/env python3
"""
Save the running 1.74 client's decrypted image, for studying its message handlers offline.

The Overwatch.exe file on disk has its code encrypted; the game decrypts it when it starts. This
reads the loaded image from memory (ReadProcessMemory only, never written) and writes it to
logs/overwatch_image.zip, with image.bin (the image, laid out at its virtual addresses) and
info.json (the load address, needed to follow pointers).

    py tools/dump_image.py        (with Overwatch.exe running and sitting at the main menu)
"""

import collections
import json
import math
import struct
import sys
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dump_schemas import ROOT, read_image

OUT = ROOT / "logs" / "overwatch_image.zip"


def entropy(data: bytes) -> float:
    counts = collections.Counter(data)
    return -sum(n / len(data) * math.log2(n / len(data)) for n in counts.values())


def text_section(img: bytes):
    """Return (rva, size) of .text from the image's own PE header."""
    pe = struct.unpack_from("<I", img, 0x3C)[0]
    sections, opt_size = struct.unpack_from("<H", img, pe + 6)[0], struct.unpack_from("<H", img, pe + 20)[0]
    first = pe + 24 + opt_size
    for i in range(sections):
        entry = first + i * 40
        if img[entry : entry + 8].rstrip(b"\0") == b".text":
            vsize, rva = struct.unpack_from("<II", img, entry + 8)
            return rva, vsize
    raise SystemExit("No .text section in the image header")


def main():
    base, img = read_image()
    rva, size = text_section(img)
    sample = img[rva : rva + min(size, 8 << 20)]
    score = entropy(sample)
    print(f"Image at 0x{base:X}, {len(img) / 1e6:.1f} MB; code entropy {score:.2f}")
    if score > 7.5:
        print("The code still looks encrypted. Wait until the main menu has loaded, then run this again.")
        return 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    info = {"base": f"0x{base:X}", "size": len(img), "text_rva": f"0x{rva:X}", "saved_at": time.time()}
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr("info.json", json.dumps(info, indent=2))
        archive.writestr("image.bin", img)
    print(f"Saved {OUT} ({OUT.stat().st_size / 1e6:.1f} MB). Send that file.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
