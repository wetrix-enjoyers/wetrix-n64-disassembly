#!/usr/bin/env python3
"""Find every place build/wetrix.elf diverges from baserom.z64.

Run inside the toolchain container:

    docker run --rm -v "$PWD:/work" -w /work wetrix-mips python3 tools/find_drift.py [section]

verify_elf.py answers "does it match?". This produces the punch list.

It walks a section against the ROM bytes at the same load address and reports
two different kinds of divergence:

  INSERTION  the ELF carries extra bytes here -- a disassembled subsegment that
             came out longer than the ROM span it describes. Detected by
             finding the smallest shift after which the two streams agree
             again. Each insertion shifts every later address.

  VALUE      a field differs but the streams stay in sync -- typically a
             pointer or %hi/%lo immediate resolved to the wrong address, which
             is a *symptom* of an insertion elsewhere rather than a cause.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

OBJDUMP = "mips-linux-gnu-objdump"

ROOT = Path.cwd()
ELF = ROOT / "build" / "wetrix.elf"
ROM = ROOT / "baserom.z64"

RE_SECTION = re.compile(
    r"^\s*(\d+)\s+(\S+)\s+([0-9a-f]{8})\s+([0-9a-f]{8})\s+([0-9a-f]{8})\s+([0-9a-f]{8})\s+2\*\*\d+\s*$"
)

RESYNC = 48       # bytes that must agree for a resync to count
MAX_EXTRA = 256   # largest insertion to look for
MAX_VALUE_DIFFS = 12


def parse_sections(output: str) -> list[dict]:
    sections = []
    lines = output.splitlines()
    for i, line in enumerate(lines):
        m = RE_SECTION.match(line)
        if not m:
            continue
        flags = lines[i + 1] if i + 1 < len(lines) else ""
        sections.append(
            {
                "name": m.group(2),
                "size": int(m.group(3), 16),
                "vma": int(m.group(4), 16),
                "lma": int(m.group(5), 16),
                "off": int(m.group(6), 16),
                "contents": "CONTENTS" in flags,
            }
        )
    return sections


def analyze(a: bytes, b: bytes, vma: int, lma: int):
    """Walk a[shift:] against b[], returning insertions and value differences."""
    insertions: list[tuple[int, int, int]] = []
    value_diffs: list[tuple[int, bytes, bytes]] = []
    shift = 0
    j = 0
    n = min(len(a), len(b))

    while j < n - RESYNC:
        if j + shift >= len(a):
            break
        if a[j + shift] == b[j]:
            j += 1
            continue

        found = None
        for e in range(4, MAX_EXTRA + 1, 4):
            end = j + shift + e + RESYNC
            if end <= len(a) and a[j + shift + e : end] == b[j : j + RESYNC]:
                found = e
                break

        if found:
            insertions.append((j, found, shift))
            shift += found
        else:
            if len(value_diffs) < MAX_VALUE_DIFFS:
                value_diffs.append((j, a[j + shift : j + shift + 4], b[j : j + 4]))
            j += 4

    return insertions, value_diffs


def main() -> int:
    want = sys.argv[1] if len(sys.argv) > 1 else None

    if not ELF.is_file() or not ROM.is_file():
        sys.exit("error: need build/wetrix.elf and baserom.z64 (build first)")

    elf = ELF.read_bytes()
    rom = ROM.read_bytes()

    out = subprocess.run([OBJDUMP, "-h", str(ELF)], capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"error: objdump failed:\n{out.stderr}")

    for s in parse_sections(out.stdout):
        if not s["contents"] or s["size"] == 0:
            continue
        if want and s["name"] != want:
            continue

        n = min(s["size"], len(elf) - s["off"])
        a = elf[s["off"] : s["off"] + n]
        b = rom[s["lma"] : s["lma"] + n]

        if a == b:
            print(f"{s['name']}: matches ROM exactly ({s['size']:#x} bytes)")
            continue

        insertions, value_diffs = analyze(a, b, s["vma"], s["lma"])
        total_extra = sum(e for _, e, _ in insertions)

        print(f"\n=== {s['name']} ===")
        print(f"  first divergence at ROM 0x{s['lma'] + (insertions or value_diffs)[0][0]:06x}")
        print(f"  insertions: {len(insertions)}  total extra bytes: {total_extra:#x}")

        for off, e, at in insertions:
            vram = s["vma"] + off
            rom_off = s["lma"] + off
            print(
                f"    +{e:#04x} at ROM 0x{rom_off:06x} / VRAM 0x{vram:08x}"
                f"   inserted: {a[off + at : off + at + e].hex()}"
            )

        if value_diffs:
            print(f"  value differences (first {len(value_diffs)}):")
            for off, got, exp in value_diffs:
                print(
                    f"    at ROM 0x{s['lma'] + off:06x} / VRAM 0x{s['vma'] + off:08x}"
                    f"   elf {got.hex()} vs rom {exp.hex()}"
                )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
