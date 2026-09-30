#!/usr/bin/env python3
"""Report which of the ELF's function symbols the ROM can actually reach.

N64Recomp compiles every function the ELF names, whether or not anything calls
it. Splat is generous about creating those names: a boundary it found while
disassembling becomes a `func_XXXXXXXX` symbol even when no `jal` and no branch
ever targets it. Two examples in this ROM, both of which branch into the middle
of a *different* function's body:

    0x80059B20  func_80059B20   branches to 0x80059B48 (inside func_80059B40)
    0x8004F510  func_8004F510   branches to 0x8004F580 (inside osAiSetFrequency)

Neither is referenced anywhere, so neither ever runs. That matters because the
branch-escaping fixer widens such a range until it ends on a terminator, which
drags the rest of the neighbouring body in and makes it look like live code
that touches hardware. Dead code touching hardware is harmless; live code
touching hardware is the crash. This separates them.

The graph itself lives in tools/reachability.py; read its docstring for the
blind spots that make "unreachable" a lead rather than a verdict.

Usage:
    python tools/find_reachable.py build/wetrix.elf [--names func_x func_y ...]
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from reachability import reachable, symbols  # noqa: E402


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    elf = sys.argv[1]

    wanted = None
    if "--names" in sys.argv:
        wanted = set(sys.argv[sys.argv.index("--names") + 1:])

    syms = symbols(elf)
    seen, _starts, _names, referenced = reachable(elf)

    print(f"{len(syms)} symbols, {len(seen)} reachable, "
          f"{len(syms) - len(seen)} unreachable")

    if wanted:
        print(f"\n{'name':<24} {'address':<10} reachable  referenced-by-code")
        for addr, name in syms:
            if name in wanted:
                print(f"{name:<24} 0x{addr:08X} "
                      f"{'yes' if addr in seen else 'NO':<10} "
                      f"{'yes' if addr in referenced else 'no'}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
