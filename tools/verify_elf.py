#!/usr/bin/env python3
"""Verify build/wetrix.elf against the original ROM, byte for byte.

Run inside the toolchain container:

    docker run --rm -v "$PWD:/work" -w /work wetrix-mips python3 tools/verify_elf.py

The link script places every section with AT(), so each output section carries
a load address (LMA) equal to its offset in baserom.z64. That makes a direct
comparison possible: for every section that actually has contents, compare the
bytes the linker laid down against the bytes at the same ROM offset.

A clean result means the reassembly reproduces the original ROM exactly, which
is a much stronger statement than the link merely succeeding -- it means the
function boundaries and addresses N64Recomp will read are the real ones.
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

# Idx  Name  Size  VMA  LMA  File-off  Algn
RE_SECTION = re.compile(
    r"^\s*(\d+)\s+(\S+)\s+([0-9a-f]{8})\s+([0-9a-f]{8})\s+([0-9a-f]{8})\s+([0-9a-f]{8})\s+2\*\*\d+\s*$"
)


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
                "has_contents": "CONTENTS" in flags,
            }
        )
    return sections


def main() -> int:
    if not ELF.is_file():
        sys.exit(f"error: {ELF} not found -- run tools/build_elf.py first")
    if not ROM.is_file():
        sys.exit(f"error: {ROM} not found")

    rom = ROM.read_bytes()
    elf = ELF.read_bytes()

    out = subprocess.run([OBJDUMP, "-h", str(ELF)], capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"error: objdump failed:\n{out.stderr}")

    sections = parse_sections(out.stdout)
    if not sections:
        sys.exit("error: could not parse any sections")

    total_bytes = 0
    total_mismatch = 0
    rows: list[tuple[str, int, int, str]] = []

    for s in sections:
        if not s["has_contents"] or s["size"] == 0:
            continue

        start, size, lma = s["off"], s["size"], s["lma"]

        if lma + size > len(rom):
            rows.append((s["name"], size, size, f"LMA 0x{lma:06x} past end of ROM"))
            total_mismatch += size
            continue

        a = elf[start : start + size]
        b = rom[lma : lma + size]

        if len(a) < size:
            rows.append((s["name"], size, size - len(a), "truncated in ELF"))
            total_mismatch += size - len(a)
            continue

        if a == b:
            rows.append((s["name"], size, 0, "match"))
        else:
            diff = sum(1 for x, y in zip(a, b) if x != y)
            first = next(i for i, (x, y) in enumerate(zip(a, b)) if x != y)
            rows.append(
                (
                    s["name"],
                    size,
                    diff,
                    f"first diff at ROM 0x{lma + first:06x}: "
                    f"elf {a[first]:02x} vs rom {b[first]:02x}",
                )
            )
            total_mismatch += diff

        total_bytes += size

    print(f"{'section':<20} {'size':>10} {'mismatch':>10}  note")
    print("-" * 78)
    for name, size, diff, note in rows:
        print(f"{name:<20} {size:>10} {diff:>10}  {note}")

    print("-" * 78)
    print(f"{total_bytes} bytes compared, {total_mismatch} mismatched")

    if total_mismatch:
        print("\nRESULT: reassembly is NOT byte-faithful")
        return 1
    print("\nRESULT: reassembly is byte-for-byte faithful to baserom.z64")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
