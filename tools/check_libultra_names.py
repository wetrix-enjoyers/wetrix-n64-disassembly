#!/usr/bin/env python3
"""Check that every name in a symbol table is one N64Recomp actually knows.

A correct name for a function buys nothing on its own. N64Recomp decides what to
hand to the runtime by *name*, against two lists compiled into it:

  * `reimplemented_funcs` -- the runtime provides an implementation, so callers
    are routed to it and the ROM body is dropped;
  * `ignored_funcs` -- the body is dropped and callers resolve against a
    `_recomp` symbol the runtime supplies.

A name on neither list is still an improvement over `func_XXXXXXXX` -- it says
what the function is -- but the ROM body is recompiled regardless, so a hardware
access in it still faults or still fails the build. Knowing which bucket each
name falls into is the difference between "named" and "fixed".

The second mode answers a different question: which addresses this map calls a
function and a reference map calls a bare label. That difference is not cosmetic.
A zero-size label is a name without a body, so N64Recomp does not recompile
anything there -- the surrounding function already holds those instructions.
Promoting it to a function makes N64Recomp emit the same bytes a second time,
and the duplicate is the one that fails, because the bodies involved read COP0
registers or touch hardware.

Usage:
    python tools/check_libultra_names.py config/us/symbol_addrs_libultra.txt \
        --lists /path/to/n64recomp/src/symbol_lists.cpp

    python tools/check_libultra_names.py --divergence \
        --other /path/to/reference-symtab.txt
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ENTRY = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*0x([0-9A-Fa-f]+)")


def load_elf_functions(path):
    """{vram: (size, name)} for the symbols in an ELF that carry a body."""
    import struct  # noqa: F401  (kept so the module reads standalone)

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from find_hardware_funcs import load_elf

    _secs, syms = load_elf(Path(path))
    out = {}
    for name, value, size, typ in syms:
        if typ == 2 and size >= 4:                      # STT_FUNC
            out.setdefault(value, (size, name))
    return out


def load_reference(path):
    """A reference `nm --defined-only` dump: address, size, type, name."""
    funcs = set()
    for line in open(path, encoding="utf-8"):
        f = line.split()
        if len(f) < 4 or f[0] == "Value":
            continue
        try:
            addr, size = int(f[0], 16), int(f[1])
        except ValueError:
            continue
        if f[2] == "FUNC" and size >= 4:
            funcs.add(addr)
    return funcs


def divergence(args) -> int:
    ours = load_elf_functions(args.elf)
    theirs = load_reference(args.other)
    # The entrypoint is deliberately a function whose rom address differs from
    # its vram, which no reference dump expresses; it is not a divergence.
    addrs = sorted(a for a in set(ours) - theirs if a != 0x80000400)

    print(f"our map: {len(ours)} functions with bytes")
    print(f"reference: {len(theirs)} function symbols")
    print(f"called a function here, a bare label there: {len(addrs)}\n")
    for a in addrs:
        size, name = ours[a]
        print(f"    {a:08X}  {size:5d}B  {name}")
    return 0


def load_lists(path):
    src = Path(path).read_text()
    out = {}
    for key in ("reimplemented_funcs", "ignored_funcs"):
        if key not in src:
            continue
        body = src.split(key, 1)[1].split("};", 1)[0]
        out[key] = set(re.findall(r'"([A-Za-z0-9_]+)"', body))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("table", nargs="?")
    ap.add_argument("--lists", help="N64Recomp's src/symbol_lists.cpp")
    ap.add_argument("--divergence", action="store_true",
                    help="compare function sets against a reference symtab instead")
    ap.add_argument("--elf", default="build/wetrix.elf")
    ap.add_argument("--other", help="reference `nm --defined-only` dump")
    args = ap.parse_args()

    if args.divergence:
        if not args.other:
            ap.error("--divergence needs --other")
        return divergence(args)

    if not args.table or not args.lists:
        ap.error("need a table and --lists (or --divergence --other)")

    lists = load_lists(args.lists)
    known = lists.get("reimplemented_funcs", set()) | lists.get("ignored_funcs", set())
    print(f"vocabulary: {len(lists.get('reimplemented_funcs', ()))} reimplemented, "
          f"{len(lists.get('ignored_funcs', ()))} ignored ({len(known)} distinct)")

    entries = []
    for line in open(args.table, encoding="utf-8"):
        m = ENTRY.match(line)
        if m:
            entries.append((m.group(1), int(m.group(2), 16)))

    buckets = {}
    for name, addr in entries:
        if name in lists.get("reimplemented_funcs", set()):
            key = "reimplemented -- callers route to the runtime"
        elif name in lists.get("ignored_funcs", set()):
            key = "ignored -- body dropped, runtime supplies _recomp"
        else:
            key = "UNKNOWN to N64Recomp -- naming alone changes nothing"
        buckets.setdefault(key, []).append((name, addr))

    print(f"{len(entries)} entries in {args.table}\n")
    for key in sorted(buckets, key=lambda k: k.startswith("UNKNOWN")):
        print(f"{len(buckets[key]):3d}  {key}")
        for name, addr in sorted(buckets[key], key=lambda e: e[1]):
            print(f"        {addr:08X}  {name}")
        print()

    unknown = buckets.get("UNKNOWN to N64Recomp -- naming alone changes nothing", [])
    return 1 if unknown else 0


if __name__ == "__main__":
    sys.exit(main())
