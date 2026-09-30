#!/usr/bin/env python3
"""Recover the audio microcode's jump-table targets from the ROM.

The microcode dispatches audio commands through a table of 16-bit jump targets:

    srl     $1, $26, 23      ; $26 = the command word
    andi    $1, $1, 0xFE     ; 16-bit entries, so an even byte offset
    lh      $2, 0x10($1)     ; the table lives at DMEM 0x10 in the ucode data
    jr      $2

Those targets exist only as data, so RSPRecomp -- which derives its indirect
branch targets from the instruction stream -- cannot find them, and every
command that dispatches to an address no other instruction mentions fails at
runtime with "Unhandled jump target". They are listed by hand in
wetrix_rsp.toml's `extra_indirect_branch_targets`, and this script derives that
list from the ROM so the two can be checked against each other.

Where the numbers come from:

* The ucode data is the 0x800 bytes the game loads into RDRAM 0x80064500, which
  the ROM holds at 0x65100 with each 4-byte group reversed (same word-swap as
  the microcode text; see wetrix_rsp.toml).
* DMEM ends up holding those bytes unchanged, because the ^ 3 in `MEM_B` (the
  recompiled code's byte accessor) and the ^ 3 in the runtime's `RSP_MEM_B`
  cancel.
* `lh $2, 0x10($2)` with $2 == a is therefore assembled from
  D[(p ^ 3) ^ 1] and D[p ^ 3], where p = 0x10 + a, and the host's little-endian
  assembly puts the first of those in the low byte.

Usage: tools/find_ucode_targets.py [--toml wetrix_rsp.toml]
"""

import argparse
import re
import sys

ROM_PATH = "baserom.z64"
# ROM offset of the microcode data, and its size. See wetrix_rsp.toml.
UCODE_DATA_ROM_OFFSET = 0x65100
UCODE_DATA_SIZE = 0x800
# The text the targets have to be in, so that values belonging to the unrelated
# audio tables the data blob also holds can be filtered out. The base is the
# address the boot microcode really runs the text at (it DMAs it to IMEM 0x1080
# and `jr $7`s there), not 0x1000 -- see wetrix_rsp.toml.
TEXT_START = 0x1080
TEXT_END = 0x1080 + 0xEA8    # one past the last instruction; see wetrix_rsp.toml
TOP_INDEX = 0x100      # (command >> 23) & 0xFE spans 0x00..0xFE


def load_ucode_data(rom_path):
    with open(rom_path, "rb") as fh:
        fh.seek(UCODE_DATA_ROM_OFFSET)
        raw = fh.read(UCODE_DATA_SIZE)
    if len(raw) != UCODE_DATA_SIZE:
        sys.exit(f"short read from {rom_path}: wanted 0x{UCODE_DATA_SIZE:X} bytes")
    # The ROM stores each 4-byte group reversed.
    return b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))


def halfword(data, a):
    """The value `lh $2, 0x10($2)` yields for $2 == a."""
    p = 0x10 + a
    return data[(p ^ 3) ^ 1] | (data[p ^ 3] << 8)


def targets(data):
    seen = []
    for a in range(0, TOP_INDEX, 2):
        value = halfword(data, a)
        if TEXT_START <= value < TEXT_END and value % 4 == 0 and value not in seen:
            seen.append(value)
    return sorted(seen)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rom", default=ROM_PATH)
    parser.add_argument("--toml", default=None,
                        help="check the list in this config against the ROM")
    args = parser.parse_args()

    found = targets(load_ucode_data(args.rom))
    print(f"{len(found)} branch targets in the microcode's jump table:")
    for value in found:
        print(f"    0x{value:04X},")

    if args.toml is None:
        return 0

    with open(args.toml) as fh:
        config = fh.read()
    match = re.search(r"extra_indirect_branch_targets\s*=\s*\[(.*?)\]", config, re.S)
    if match is None:
        sys.exit(f"{args.toml} has no extra_indirect_branch_targets list")
    listed = sorted(int(m, 0) for m in re.findall(r"0x[0-9A-Fa-f]+", match.group(1)))

    if listed == found:
        print(f"\n{args.toml} matches the ROM.")
        return 0
    print(f"\n{args.toml} disagrees with the ROM:", file=sys.stderr)
    print(f"    only in config: {[hex(v) for v in set(listed) - set(found)]}", file=sys.stderr)
    print(f"    only in ROM:    {[hex(v) for v in set(found) - set(listed)]}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
