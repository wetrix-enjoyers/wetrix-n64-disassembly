#!/usr/bin/env python3
"""Find functions whose recompiled body was silently cut short.

N64Recomp emits one C function per ELF function symbol and trusts the symbol's
size. When splat splits a real function in two -- because the ROM `jal`s a label
that lives in the middle of the body, the "two entry points share one body"
pattern -- the outer symbol keeps only the prologue. A prologue has no `jr ra` in
it, so the generated C falls off its own end and the function does nothing.

That is not a compile error and not a link error, so the only way to catch it is
to look at the actual bytes: a complete MIPS function ends with `jr $ra` (or a
tail `j`/`jal`/`eret`) followed by a delay slot, so every real function has a
terminator in its last two instructions. This reads those two words straight out
of the ELF and reports the functions that do not.

The fix for each is a `function_sizes` widening that absorbs the split-off body,
plus a stub for any dead caller of the absorbed entry -- see osCreateScheduler in
wetrix.toml for the worked example.

Usage: python tools/find_truncated.py [--elf build/wetrix.elf]
"""

import argparse
import os
import re
import struct
import subprocess
import sys

# N64Recomp drops the ROM body for any name on its built-in lists (reimplemented,
# ignored) and for every `stubs` entry, so a missing terminator in one of those
# is not a bug. `function_sizes` widens a function past a bad ELF boundary, so an
# override there means the truncation is already handled.
SIZE_ENTRY_RE = re.compile(r'\{\s*name\s*=\s*"([^"]+)"\s*,\s*size\s*=\s*(0x[0-9A-Fa-f]+|\d+)')

READELF = os.environ.get("READELF", "readelf")

SECTION_RE = re.compile(
    r"^\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)"
)
# readelf prints Value as hex and Size as decimal -- mixing them up silently
# misplaces every function, so the two are parsed with the right base.
SYMBOL_RE = re.compile(
    r"^\s*\d+:\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S+)\s+\S+\s+\S+\s+\S+\s+(\S+)$"
)


def run_readelf(args):
    return subprocess.run(
        [READELF, *args], capture_output=True, text=True, check=True
    ).stdout


def load_sections(elf):
    sections = []
    for line in run_readelf(["-SW", elf]).splitlines():
        m = SECTION_RE.match(line)
        if not m:
            continue
        name, _type, addr, off, size = m.groups()
        sections.append((int(addr, 16), int(off, 16), int(size, 16), name))
    return sections


def vaddr_to_offset(sections, vaddr):
    for addr, off, size, _name in sections:
        if addr <= vaddr < addr + size:
            return off + (vaddr - addr)
    return None


def load_functions(elf):
    funcs = []
    for line in run_readelf(["-sW", elf]).splitlines():
        m = SYMBOL_RE.match(line)
        if not m:
            continue
        value, size, type_, name = m.groups()
        if type_ == "FUNC" and int(size) > 0:
            funcs.append((int(value, 16), int(size), name))
    return funcs


def load_overrides(toml_path):
    """Return (widened_sizes, dropped_names) from wetrix.toml and N64Recomp."""
    widened = {}
    dropped = set()
    try:
        text = open(toml_path, "r", encoding="utf-8").read()
    except OSError:
        return widened, dropped

    for name, size in SIZE_ENTRY_RE.findall(text):
        widened[name] = int(size, 16) if size.lower().startswith("0x") else int(size)

    m = re.search(r"stubs\s*=\s*\[(.*?)\]", text, re.S)
    if m:
        dropped.update(re.findall(r'"([^"]+)"', m.group(1)))

    lists_path = "build/n64recomp/src/symbol_lists.cpp"
    if os.path.exists(lists_path):
        dropped.update(re.findall(r'"([^"]+)"', open(lists_path, encoding="utf-8").read()))

    return widened, dropped


def terminates(word):
    """True if a raw MIPS instruction word is a function-ending terminator."""
    opcode = word >> 26
    funct = word & 0x3F
    if opcode == 0:
        # SPECIAL: jr (8), break (13), syscall (12). jalr (9) is a tail call too.
        return funct in (8, 9, 12, 13)
    if opcode in (2, 3):  # j / jal
        return True
    if opcode == 0x10:  # COP0: eret is 0x42000018
        return word == 0x42000018
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--elf", default="build/wetrix.elf")
    ap.add_argument("--toml", default="wetrix.toml")
    args = ap.parse_args()

    if not os.path.exists(args.elf):
        sys.exit(f"no such file: {args.elf}")

    sections = load_sections(args.elf)
    funcs = load_functions(args.elf)
    widened, dropped = load_overrides(args.toml)

    with open(args.elf, "rb") as fh:
        image = fh.read()

    offenders = []
    tiny = []
    for vaddr, size, name in funcs:
        if name in dropped:
            continue
        size = widened.get(name, size)
        if size < 8:
            tiny.append((vaddr, size, name))
            continue
        end = vaddr + size
        words = []
        for va in (end - 8, end - 4):
            off = vaddr_to_offset(sections, va)
            if off is None or off + 4 > len(image):
                words = None
                break
            # The target ELF is big-endian MIPS, and the file stores the
            # instructions in that byte order too.
            words.append(struct.unpack_from(">I", image, off)[0])
        if words is None:
            continue
        if not any(terminates(w) for w in words):
            offenders.append((vaddr, size, name))

    print(f"{len(funcs)} FUNC symbols in {args.elf}")
    print(f"{len(widened)} size overrides and {len(dropped)} dropped names applied")
    print(f"{len(offenders)} still do not end in a terminator (body cut short):")
    for vaddr, size, name in offenders:
        print(f"  {name:<28} 0x{vaddr:08X}  size 0x{size:X}")
    if tiny:
        print(f"\n{len(tiny)} symbols smaller than 8 bytes (checked manually):")
        for vaddr, size, name in tiny:
            print(f"  {name:<28} 0x{vaddr:08X}  size 0x{size:X}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
