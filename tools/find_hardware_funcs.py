#!/usr/bin/env python3
"""Which still-unnamed functions touch hardware the runtime has to own.

N64Recomp decides what to hand to N64ModernRuntime **by name**. A function whose
ELF symbol is `osAiSetFrequency` is on its reimplemented list and the ROM body is
dropped in favour of the runtime's; the same bytes under the name
`func_8005B91C` get recompiled instruction by instruction, and then:

  * a memory-mapped access (0xA4xxxxxx-0xA8xxxxxx) is translated by the MEM_*
    macros into an offset from rdram, lands past the end of the 8 MB allocation,
    and takes an access violation at run time; and
  * a COP0 access has no MEM_* form at all, so it is a raw cop0 intrinsic that
    the compiler rejects -- `func_80060A00` is `mtc0 $11` and fails the build.

Both are fixed the same way, by putting the right name in a symbol table, which
is why this reports rather than patches. It reads the ELF and the ROM only, so it
works before the recompile is clean -- which it cannot be until the names exist.

What it cannot do is choose the name. That is a reading of each function: the
hardware block it addresses (`lui 0xA460` is the parallel interface, `0xA440` the
video interface, `0xA450` audio, `0xA404`/`0xA410` the RSP) and which COP0 register
it moves (`$9` Count, `$11` Compare, `$12` Status, `$13` Cause, `$14` EPC, `$30`
FCR). N64Recomp's reimplemented_funcs list -- `src/symbol_lists.cpp` in its tree --
is the vocabulary the answer has to come from, since a name it does not know buys
nothing.

Usage:
    python tools/find_hardware_funcs.py [--elf build/wetrix.elf] [--rom baserom.z64]
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

# Hardware block by the top half of the address, for the report. Complete for the
# ranges this ROM touches; anything else prints the raw value.
BLOCKS = {
    0xA404: "SP registers", 0xA408: "SP PC", 0xA410: "DP command",
    0xA420: "DP span", 0xA430: "MI", 0xA440: "VI", 0xA450: "AI",
    0xA460: "PI", 0xA470: "RI", 0xA480: "SI", 0xA500: "SI",
}

COP0_REGS = {
    8: "BadVAddr", 9: "Count", 10: "EntryHi", 11: "Compare", 12: "Status",
    13: "Cause", 14: "EPC", 15: "PRId", 16: "Config", 30: "FCR",
}

LOADS_STORES = {0x20, 0x21, 0x23, 0x24, 0x25, 0x27, 0x28, 0x29, 0x2B, 0x2F}


def load_elf(path: Path):
    """Sections and symbols of a 32-bit big-endian ELF, in that order."""
    d = path.read_bytes()
    if d[:4] != b"\x7fELF" or d[4] != 1:
        raise SystemExit(f"{path}: not a 32-bit ELF")
    if d[5] != 2:
        raise SystemExit(f"{path}: expected the big-endian ELF the linker writes")
    shoff = struct.unpack_from(">I", d, 0x20)[0]
    shentsize, shnum = struct.unpack_from(">HH", d, 0x2E)
    shstrndx = struct.unpack_from(">H", d, 0x32)[0]
    secs = []
    for i in range(shnum):
        o = shoff + i * shentsize
        name, _, _, addr, off, size, link, _, _, _ = struct.unpack_from(">IIIIIIIIII", d, o)
        secs.append(dict(name=name, addr=addr, off=off, size=size, link=link))
    shstr = secs[shstrndx]["off"]
    for s in secs:
        end = d.index(b"\0", shstr + s["name"])
        s["sname"] = d[shstr + s["name"]:end].decode()

    symsec = next(s for s in secs if s["sname"] == ".symtab")
    strs = d[secs[symsec["link"]]["off"]:]
    syms = []
    for i in range(symsec["size"] // 16):
        o = symsec["off"] + i * 16
        st_name, st_value, st_size, st_info, _, st_shndx = struct.unpack_from(">IIIBBH", d, o)
        if st_shndx == 0 or st_name == 0:
            continue
        name = strs[st_name:strs.index(b"\0", st_name)].decode()
        syms.append((name, st_value, st_size, st_info & 0xF))
    return secs, syms


def hardware_sites(words, value):
    """(address, description) for every hardware touch in a function body."""
    out = []
    address_regs = set()
    for i in range(0, len(words) * 4, 4):
        w = words[i // 4]
        pc, op = value + i, w >> 26

        if op == 0x10:
            co, rs, rd = (w >> 25) & 1, (w >> 21) & 0x1F, (w >> 11) & 0x1F
            mnem = ({0: "mfc0", 4: "mtc0"} if not co else {2: "cfc0", 6: "ctc0"}).get(rs)
            if mnem:
                out.append((pc, f"{mnem} ${rd} ({COP0_REGS.get(rd, '?')})"))
            elif w in (0x42000018, 0x42000038):
                out.append((pc, "eret/tlb"))
            continue

        if op == 0x0F:                                  # lui rt, imm
            rt, imm = (w >> 16) & 0x1F, w & 0xFFFF
            if 0xA400 <= imm <= 0xA8FF or imm in BLOCKS:
                address_regs.add(rt)
                out.append((pc, f"lui 0x{imm:04X} ({BLOCKS.get(imm, 'hardware')})"))
            elif rt in address_regs:
                address_regs.discard(rt)
            continue

        if op in LOADS_STORES:
            rs = (w >> 21) & 0x1F
            if rs in address_regs:
                out.append((pc, "access through a hardware address register"))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--elf", default="build/wetrix.elf")
    ap.add_argument("--rom", default="baserom.z64")
    ap.add_argument("--segment", default=".main")
    ap.add_argument("--all", action="store_true",
                    help="include functions that already have a name")
    args = ap.parse_args()

    import yaml

    secs, syms = load_elf(Path(args.elf))
    rom = Path(args.rom).read_bytes()
    text = next(s for s in secs if s["sname"] == args.segment)

    # The ELF's file offsets and the ROM's differ by a constant per segment, so
    # the rom <-> vram mapping comes from the config rather than from a section.
    doc = yaml.safe_load(Path("wetrix.yaml").read_text())
    seg = next(s for s in doc["segments"] if s.get("name") == "main")
    seg_rom, seg_vram = seg["start"], seg["vram"]

    def word(vram: int) -> int:
        return struct.unpack_from(">I", rom, seg_rom + (vram - seg_vram))[0]

    hits = []
    for name, value, size, typ in syms:
        if typ != 2 or size < 4:                        # STT_FUNC
            continue
        if not (text["addr"] <= value < text["addr"] + text["size"]):
            continue
        words = [word(value + i) for i in range(0, size, 4)]
        sites = hardware_sites(words, value)
        if sites:
            hits.append((name, value, size, sites))

    unnamed = [h for h in hits if h[0].startswith("func_")]
    if not args.all:
        hits = unnamed

    print(f"{len(hits)} functions touch hardware"
          f" ({len(unnamed)} of them still unnamed)")
    print()
    for name, value, size, sites in sorted(hits, key=lambda h: h[1]):
        print(f"{name:22} {value:08X}  {size:5d}B  {len(sites):3d} sites")
        for pc, what in sites[:4]:
            print(f"        {pc:08X}  {what}")
        if len(sites) > 4:
            print(f"        ... and {len(sites) - 4} more")
    return 0


if __name__ == "__main__":
    sys.exit(main())
