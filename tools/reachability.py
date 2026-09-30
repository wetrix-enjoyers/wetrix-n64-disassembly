#!/usr/bin/env python3
"""Static call-graph reachability for the recompiled ELF.

Kept separate from the tools that use it because two of them need the same
answer: `find_reachable.py` reports it, and `find_mmio_sites.py` uses it to tell
a live hardware access from one sitting in dead code.

Reachability is computed over the ROM's own call graph: nodes are the ELF's
function symbols, edges are `jal` and branches that land on a symbol address.
Roots are the entrypoint, the game's `main`, and every symbol named `Thread_*`
(the ROM starts those from a table in data, so no code edge points at them).

A function whose *name* is on N64Recomp's reimplemented or ignored list is
compiled away -- the runtime supplies it instead. Those bodies do not run, so
they are neither reported as reachable nor followed: a call site inside one of
them is a call that will not be emitted. Skipping them matters more than it
sounds. `osJamMesg` in this ROM is a single symbol covering 0x824 bytes that is
really a dozen small functions, and it is on the reimplemented list, so every
call inside it is dead -- including the nine that looked like they made
func_80051EE4 live.

Two remaining blind spots, both making the result *under*-report reachability:

  * an indirect `jalr` is invisible, so a function only reached that way looks
    unreachable;
  * a thread entry not named `Thread_*` and not called is unreachable to this
    analysis but obviously not to the game.

So "unreachable" is a lead to verify, never a verdict. In practice it is worth
using anyway, because the alternative is treating a phantom function's dead
branch as a live fault.
"""

import bisect
import re
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path

INSN_RE = re.compile(r"^\s*([0-9a-f]{8}):\t[0-9a-f]{8}\s+(\S+)\s*(.*)$")
ADDR_RE = re.compile(r"^([0-9a-f]{8})\b")

BRANCHES = {"b", "beq", "bne", "beqz", "bnez", "bgez", "bgtz", "blez", "bltz",
            "beql", "bnel", "beqzl", "bnezl", "bgezl", "bgtzl", "blezl",
            "bltzl", "bgezal", "bltzal", "bgezall", "bltzall", "bal", "j"}


def tool(base):
    """Prefer the MIPS-prefixed binutils; a native objdump cannot read MIPS."""
    for candidate in (f"mips-linux-gnu-{base}", base):
        if shutil.which(candidate):
            return candidate
    raise SystemExit(f"no {base} available")


def dropped_names(recompiler="build/n64recomp", toml="wetrix.toml"):
    """Names whose ROM body N64Recomp drops in favour of a host implementation.

    reimplemented_funcs and ignored_funcs are both compiled away; renamed_funcs
    are renamed but *still recompiled*, so they keep running and are not here.
    """
    names = set()
    lists = Path(recompiler) / "src" / "symbol_lists.cpp"
    if lists.exists():
        text = lists.read_text(errors="replace")
        for key in ("reimplemented_funcs", "ignored_funcs"):
            start = text.find(key)
            if start < 0:
                continue
            names.update(re.findall(r'"([^"]+)"', text[start:text.find("\n};", start)]))
    toml_path = Path(toml)
    if toml_path.exists():
        text = toml_path.read_text(errors="replace")
        m = re.search(r"^stubs = \[(.*?)^\]", text, re.S | re.M)
        if m:
            names.update(re.findall(r'"([^"]+)"', m.group(1)))
    return names


def symbols(elf):
    """(address, name) for every defined function-ish symbol, address-sorted."""
    out = subprocess.run([tool("nm"), "--numeric-sort", "--defined-only", elf],
                         capture_output=True, text=True, check=True).stdout
    syms = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[1] not in ("T", "t", "W", "w"):
            continue
        try:
            syms.append((int(parts[0], 16), parts[2]))
        except ValueError:
            continue
    return syms


def reachable(elf):
    """Return (reachable address set, set of all symbol addresses, name map)."""
    syms = symbols(elf)
    starts = {addr for addr, _ in syms}
    name_of = dict(syms)
    ordered = sorted(starts)

    def owner(addr):
        i = bisect.bisect_right(ordered, addr) - 1
        return ordered[i] if i >= 0 else None

    edges = defaultdict(set)
    referenced = set()
    current = None

    out = subprocess.run([tool("objdump"), "-d", elf], capture_output=True,
                         text=True, check=True).stdout
    for line in out.splitlines():
        m = INSN_RE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        mnemonic, operands = m.group(2), m.group(3)

        if addr in starts:
            current = addr

        if mnemonic.startswith("jal"):
            target = ADDR_RE.match(operands)
            if target:
                target = int(target.group(1), 16)
                referenced.add(target)
                src = current if current is not None else owner(addr)
                if src is not None and target in starts:
                    edges[src].add(target)
            continue

        if mnemonic in BRANCHES:
            target = ADDR_RE.match(operands.split(",")[-1].strip())
            if target:
                target = int(target.group(1), 16)
                if target in starts:
                    referenced.add(target)
                    src = current if current is not None else owner(addr)
                    if src is not None:
                        edges[src].add(target)

    dropped = dropped_names()

    def is_dropped(addr):
        return name_of.get(addr) in dropped

    roots = {addr for addr, name in syms
             if (name in ("recomp_entrypoint", "main") or name.startswith("Thread"))
             and name not in dropped}

    seen = set(roots)
    work = list(roots)
    while work:
        for nxt in edges[work.pop()]:
            if nxt in seen or is_dropped(nxt):
                continue
            seen.add(nxt)
            work.append(nxt)

    return seen, starts, name_of, referenced
