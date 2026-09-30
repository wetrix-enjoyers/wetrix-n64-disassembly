#!/usr/bin/env python3
"""List jump-table entry points that the splat split does not call functions.

The ROM dispatches on command bytes through tables of function addresses (the
sequence player's D_8007AC80, indexed by `byte & 0x7F`, is the one that boots
into the problem). Some of those words point *inside* a function that splat
emitted, because only `jal` targets become boundaries: spimdisasm cannot see an
indirect call, so the handler behind a table word is invisible to it.

That is fine for the disassembly and fatal for the port. N64Recomp emits one
callable function per ELF function and resolves an indirect call through the
runtime's `get_function()`, which walks that function map -- so the first time a
table-dispatched handler runs, the process dies with

    Failed to find function at 0x8004B940

`manual_funcs` in wetrix.toml is N64Recomp's escape hatch: it recompiles an extra
function at a given vram for a given size, independently of the ELF boundaries.
A duplicate body is harmless, because nothing calls it except the indirect jump.

This finds the candidates. Every 32-bit word in the segment's data is read as an
address; any that lands inside the code but is not already a function start is a
candidate, and its size runs to the end of the function that currently contains
it, so the copied body keeps that function's `jr $ra`.

Not every candidate is a call target -- a data word can hold an address for
reasons that are not dispatch -- but a wrong entry costs a duplicated body and
nothing else, while a missing one is a crash on a code path the game does reach.

Usage:
    venv/Scripts/python tools/find_jump_table_entries.py [--rom baserom.z64]
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from find_hardware_funcs import load_elf  # noqa: E402

STT_FUNC = 2


def functions(elf: Path) -> list[tuple[int, int, str]]:
    """(start, size, name) for every symbol that carries a body."""
    _secs, syms = load_elf(elf)
    out = []
    for name, value, size, typ in syms:
        if typ == STT_FUNC and size >= 4:
            out.append((value, size, name))
    return sorted(out)


def subsegment_ranges(yaml_path: Path, kinds: tuple[str, ...]) -> list[tuple[int, int]]:
    """(rom offset, vram) ranges of the subsegments whose type is in `kinds`.

    Both pieces matter here and for different reasons. The code ranges come from
    the `asm` subsegments rather than from the span the functions cover, because
    the functions also cover the segment's read-only data: every pointer into a
    string or a table would otherwise read as a pointer into code, which is how
    the first version of this reported 242 candidates instead of a handful. The
    data ranges are where candidates are looked for.
    """
    config = yaml.safe_load(yaml_path.read_text())
    out = []
    for segment in config.get("segments", []):
        # splat's schema allows a segment to be a bare list in some places, and
        # this ROM's file has one; only the dict form carries subsegments.
        if not isinstance(segment, dict):
            continue
        subs = segment.get("subsegments", [])
        vram_base = segment.get("vram", 0)
        start_base = segment.get("start", 0)
        for index, sub in enumerate(subs):
            if not isinstance(sub, list) or len(sub) != 2:
                continue
            start, kind = sub
            if kind not in kinds:
                continue
            end = subs[index + 1][0] if index + 1 < len(subs) else start
            if end <= start:
                continue
            out.append((start, end, vram_base + start - start_base))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--elf", default="build/wetrix.elf")
    ap.add_argument("--rom", default="baserom.z64")
    ap.add_argument("--yaml", default="wetrix.yaml")
    args = ap.parse_args()

    funcs = functions(Path(args.elf))
    starts = {start for start, _size, _name in funcs}
    rom = Path(args.rom).read_bytes()
    ranges = subsegment_ranges(Path(args.yaml), ("data", "rodata"))
    code = subsegment_ranges(Path(args.yaml), ("asm", "hasm", "code"))

    def in_code(addr: int) -> bool:
        return any(lo <= addr < lo + size for _off, size, lo in
                   ((o, s - o, v) for o, s, v in code))

    # Which function contains an address, so a candidate's size can run to that
    # function's end rather than to the next boundary after it.
    def enclosing(addr: int):
        for start, size, name in funcs:
            if start <= addr < start + size and addr != start:
                return start, size, name
        return None

    seen: dict[int, tuple[int, str]] = {}
    for lo, hi, _vram in ranges:
        for off in range(lo, hi - 3, 4):
            word = struct.unpack_from(">I", rom, off)[0]
            if not in_code(word) or word in starts:
                continue
            holder = enclosing(word)
            if holder is None:
                continue
            start, size, name = holder
            # Skip a candidate that a previous one already covered: a table can
            # name two handlers inside the same function.
            if word in seen:
                continue
            seen[word] = (start + size - word, name)

    code_span = (min(lo for _o, _s, lo in code), max(lo + s - o for o, s, lo in code))
    print(f"code 0x{code_span[0]:08X}..0x{code_span[1]:08X} in {len(code)} subsegments, "
          f"{len(funcs)} functions")
    print(f"scanned {len(ranges)} data ranges in {args.rom}\n")

    if not seen:
        print("no jump-table entry points found")
        return 0

    print(f"manual_funcs = [{len(seen)} entries, from "
          f"0x{min(seen):08X} to 0x{max(seen):08X}]")
    for addr in sorted(seen):
        size, holder = seen[addr]
        print(f'    {{ name = "func_{addr:08X}", section = ".main", '
              f'vram = 0x{addr:08X}, size = 0x{size:X} }},  # inside {holder}')
    return 0


if __name__ == "__main__":
    sys.exit(main())
