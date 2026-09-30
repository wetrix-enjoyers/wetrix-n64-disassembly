#!/usr/bin/env python3
"""Report ROM functions the runtime implements that this map still recompiles.

N64Recomp routes a function to the runtime **by name**. A function whose name is
in its `reimplemented_funcs` or `ignored_funcs` list is renamed to
`<name>_recomp` and its ROM body is dropped, so every caller reaches the
runtime's implementation instead. The same bytes under the name `func_80059040`
are recompiled instruction by instruction -- and the hardware accesses inside
them are translated by the MEM_* macros into offsets from the 8 MB rdram
allocation, which is to say they write to emulated RAM and are read by nothing.

That failure is quiet, which is what makes it expensive. `func_80059040` is
`osPiStartDma`: the recompiled body wrote PI registers that do not exist, the
caller waited for a DMA completion that could never arrive, and the port booted
to a black screen with every thread parked and no crash to point at.

`check_libultra_names.py` answers "is the name I picked one N64Recomp knows".
This answers the question that has to come first: **which functions should have
a name at all**. The reference symbol table is the oracle -- a full `nm` dump of
the same ROM, so every address in it carries whatever name the reference map
settled on -- and N64Recomp's own two lists say which of those names the runtime
answers for.

A candidate is only actionable if the runtime defines `<name>_recomp`: naming a
function that has no implementation turns a silent hardware access into a link
error. `--runtime` and `--port` are scanned for exactly that, so a candidate
without one is reported as such instead of recommended.

Usage:
    python tools/check_name_coverage.py \
        --reference build/reference-symtab.txt \
        --lists ../wetrix-n64-recompilation/build/n64modernruntime/N64Recomp/src/symbol_lists.cpp \
        --runtime ../wetrix-n64-recompilation/build/n64modernruntime \
        --port ../wetrix-n64-recompilation/src
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_libultra_names import load_lists  # noqa: E402

# The reference dump is `nm --defined-only`: address, size, type letter, name.
REF_LINE = re.compile(r"^([0-9A-Fa-f]+)\s+([0-9A-Fa-f]+)\s+([A-Za-z])\s+(\S+)$")

# A splat symbol table entry: `name = 0xADDR; // type:func`.
OURS_LINE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*0x([0-9A-Fa-f]+)\s*;(.*)$")

# A `<name>_recomp` the runtime actually defines, as opposed to one it calls.
RECOMP_DEF = re.compile(r"\bvoid\s+([A-Za-z_][A-Za-z0-9_]*)_recomp\s*\(")

SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".h", ".hpp")

DEFAULT_TABLES = ("config/us/symbol_addrs.txt", "config/us/symbol_addrs_libultra.txt")


def load_reference(path: Path) -> dict[int, str]:
    """{vram: name} for every text symbol in a reference `nm` dump."""
    out: dict[int, str] = {}
    for line in open(path, encoding="utf-8"):
        m = REF_LINE.match(line.strip())
        if m is not None and m.group(3).upper() == "T":
            out.setdefault(int(m.group(1), 16), m.group(4))
    return out


def load_ours(paths) -> tuple[dict[int, str], dict[int, str]]:
    """{vram: name} and {vram: kind} for this map's own symbol tables.

    `kind` is "label" for an entry splat was told is not a function. A label is
    worth distinguishing: it names an address without claiming a body, so a
    vocabulary name that lands on one is a different repair from a name that is
    simply missing.
    """
    names: dict[int, str] = {}
    kinds: dict[int, str] = {}
    for path in paths:
        for line in open(path, encoding="utf-8"):
            m = OURS_LINE.match(line.strip())
            if m is None:
                continue
            addr = int(m.group(2), 16)
            names[addr] = m.group(1)
            kinds[addr] = "label" if "type:label" in m.group(3) else "func"
    return names, kinds


def recomp_definitions(root: Path) -> set[str]:
    """Every `<name>_recomp` defined under `root`, without the suffix."""
    out: set[str] = set()
    for path in root.rglob("*"):
        if path.suffix not in SOURCE_SUFFIXES or not path.is_file():
            continue
        out.update(RECOMP_DEF.findall(path.read_text(encoding="utf-8", errors="ignore")))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reference", default="build/reference-symtab.txt",
                    help="reference `nm --defined-only` dump")
    ap.add_argument("--lists", required=True, help="N64Recomp's src/symbol_lists.cpp")
    ap.add_argument("--tables", nargs="*", default=list(DEFAULT_TABLES),
                    help="this map's symbol_addrs files")
    ap.add_argument("--runtime", help="n64modernruntime tree, to check for implementations")
    ap.add_argument("--port", help="the port's source tree, for the shims it adds")
    args = ap.parse_args()

    lists = load_lists(Path(args.lists))
    vocab = lists.get("reimplemented_funcs", set()) | lists.get("ignored_funcs", set())

    reference = load_reference(Path(args.reference))
    ours, kinds = load_ours([Path(p) for p in args.tables])

    implemented: set[str] = set()
    for root in (args.runtime, args.port):
        if root:
            implemented |= recomp_definitions(Path(root))

    print(f"reference: {len(reference)} text symbols")
    print(f"vocabulary: {len(vocab)} names the runtime answers for")
    print(f"this map: {len(ours)} named addresses in {len(args.tables)} table(s)")
    if implemented:
        print(f"implementations found: {len(implemented)} `<name>_recomp` definitions")

    agreeing = 0
    actionable: list[tuple[int, str, str]] = []
    blocked: list[tuple[int, str, str]] = []

    for addr in sorted(reference):
        ref_name = reference[addr]
        if ref_name not in vocab:
            continue

        our_name = ours.get(addr)
        if our_name == ref_name and kinds.get(addr) == "func":
            agreeing += 1
            continue

        if our_name is None:
            state = "not named at all"
        elif our_name == ref_name:
            state = f"named {our_name}, but as a label"
        else:
            state = f"named {our_name} instead"

        # A name with no implementation behind it cannot be adopted: N64Recomp
        # would emit a call to a `_recomp` nothing defines. When no --runtime or
        # --port was given every candidate is listed, because the check could not
        # be made rather than because it failed.
        if implemented and ref_name not in implemented:
            blocked.append((addr, ref_name, state))
        else:
            actionable.append((addr, ref_name, state))

    print(f"\n{agreeing} already route to the runtime under the right name\n")

    print(f"{len(actionable)} to name (the runtime defines each one):")
    for addr, name, state in actionable:
        print(f"    {addr:08X}  {name:32s} {state}")

    if blocked:
        print(f"\n{len(blocked)} the runtime does not implement -- naming these "
              f"will not link:")
        for addr, name, state in blocked:
            print(f"    {addr:08X}  {name:32s} {state}")

    return 1 if actionable else 0


if __name__ == "__main__":
    sys.exit(main())
