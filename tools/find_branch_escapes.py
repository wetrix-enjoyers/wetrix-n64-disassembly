#!/usr/bin/env python3
"""Find every branch in the ROM that leaves its own function.

N64Recomp recompiles one function at a time and can only emit a branch that
lands either inside the same function or exactly on another function's start
(which it turns into a tail call). Anything else is either a hard error
("Unhandled branch") or a warning that produces a goto to a label that does not
exist. The recompiler stops at the first hard error, so chasing these one at a
time costs a full rebuild each.

They are all one cause: `gcc` cross-jumps identical code tails, so a function
ends by branching forward into the *epilogue of the next function* instead of
duplicating those instructions. The fix is to widen the branching function with
N64Recomp's `function_sizes` override so the shared tail falls inside it, which
recompiles the tail twice -- exactly the duplication the original compiler
declined to do.

Widening has to be iterative. The shared tail is often itself the next
function's body, which branches onward again, so one pass leaves the new
boundary short. This walks each function out to a fixpoint: absorb the function
owning a target, then rescan the widened range for further escapes.

Reports (and reads) the `function_sizes` block already in wetrix.toml, so it can
be run repeatedly and its output pasted back in.

Usage (inside the container):
    python3 tools/find_branch_escapes.py build/wetrix.elf wetrix.toml
"""

import re
import subprocess
import sys
from pathlib import Path

# Branch mnemonics that encode an absolute target. `jr`/`jalr` and the jump
# tables are deliberately absent: those are register-relative and N64Recomp
# resolves them through its jump table metadata instead.
BRANCHES = {
    "b", "bal", "beq", "bne", "beqz", "bnez", "beql", "bnel", "beqzl", "bnezl",
    "bgez", "bgtz", "blez", "bltz", "bgezal", "bltzal", "bgezl", "bgtzl",
    "blezl", "bltzl", "bgezall", "bltzall", "j", "jal",
}

# readelf numbers its symbols, so the first column carries a trailing colon.
SYM_RE = re.compile(r"^([0-9a-f]+):?\s+([0-9a-f]+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$")
DIS_RE = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f ]+?)\s*\t(\S+)\s*(.*)$")
HEX8 = re.compile(r"^[0-9a-f]{8}$")

MAX_GROWTH = 0x4000     # a function that needs more than this is a red flag


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout


def parse_symbols(elf):
    """Return {vram: (name, size)} for STT_FUNC symbols with a nonzero size.

    That is exactly the set N64Recomp recompiles: it computes
    `num_instructions = size / 4` and drops anything resulting in zero, so
    STT_NOTYPE symbols and zero-sized FUNC symbols never get a body.

    NOTE: readelf prints Value in hex but Size in DECIMAL, which is easy to get
    wrong -- parsing the size as hex turns a 48-byte function into a 0x48-byte
    one and invents overlaps that do not exist.
    """
    out = run(["mips-linux-gnu-readelf", "-sW", elf])
    funcs = {}
    for line in out.splitlines():
        m = SYM_RE.match(line.strip())
        if not m:
            continue
        _num, value, size, type_, _bind, _vis, _ndx, name = m.groups()
        if type_ != "FUNC" or int(size, 10) == 0:
            continue
        funcs[int(value, 16)] = (name, int(size, 10))
    print(f"parsed {len(funcs)} recompiled function(s)", file=sys.stderr)
    return funcs


def parse_all_symbol_addrs(elf):
    """Every defined symbol address, of any type.

    N64Recomp accepts a branch that lands on *any* known symbol as a tail call,
    not just on STT_FUNC ones -- it creates dummy function entries for
    STT_NOTYPE and STT_OBJECT symbols purely so their addresses can be looked
    up. Restricting this set to typed functions reports escapes that the
    recompiler is perfectly happy with.
    """
    out = run(["mips-linux-gnu-readelf", "-sW", elf])
    addrs = set()
    for line in out.splitlines():
        m = SYM_RE.match(line.strip())
        if not m:
            continue
        _num, value, _size, type_, _bind, _vis, _ndx, name = m.groups()
        if int(value, 16) == 0:
            continue
        if type_ in ("SECTION", "FILE"):
            continue
        # Splat's `.L` labels are local to a subsegment and N64Recomp cannot see
        # them -- it only knows the symbols it finds in the ELF, and a local
        # label is not a callable address to it. Treating one as a valid branch
        # target makes the recompiler emit a goto to a label it never defines,
        # so exclude them here too and let them be reported as escapes.
        if name.startswith(".L"):
            continue
        addrs.add(int(value, 16))
    return addrs


def parse_disassembly(elf):
    """Return {vram: (mnemonic, operand_text)} for the whole ELF."""
    out = run(["mips-linux-gnu-objdump", "-d", elf])
    insns = {}
    for line in out.splitlines():
        m = DIS_RE.match(line)
        if not m:
            continue
        addr, word, mnem, ops = m.groups()
        insns[int(addr, 16)] = (mnem, ops, int("".join(word.split()), 16))
    print(f"parsed {len(insns)} instruction(s)", file=sys.stderr)
    return insns


def read_overrides(toml_path):
    """Current `function_sizes` from wetrix.toml, as {name: size}."""
    path = Path(toml_path)
    if not path.exists():
        return {}
    m = re.search(r"function_sizes\s*=\s*\[(.*?)\]", path.read_text(errors="replace"), re.S)
    if not m:
        return {}
    found = re.findall(r'name\s*=\s*"([^"]+)"[^}]*?size\s*=\s*([0-9A-Fa-fx]+)', m.group(1))
    return {name: int(size, 0) for name, size in found}


def skip_names():
    """Libultra names N64Recomp replaces or drops, plus our own stubs.

    Escapes inside those functions are irrelevant because their bodies are
    never recompiled. The built-in lists live in the recompiler checkout; if it
    is not present we simply check everything.
    """
    names = set()
    lists = Path("build/n64recomp/src/symbol_lists.cpp")
    if lists.exists():
        names.update(re.findall(r'"([^"]+)"', lists.read_text(errors="replace")))
    toml = Path("wetrix.toml")
    if toml.exists():
        text = toml.read_text(errors="replace")
        m = re.search(r"^stubs = \[(.*?)^\]", text, re.S | re.M)
        if m:
            names.update(re.findall(r'"([^"]+)"', m.group(1)))
    return names


TERMINATORS = {"jr", "j", "eret"}


def redirect_target(target, insns, starts):
    """If `target` is a run of nops leading into a function start, return it.

    A branch to the delay-slot nop that follows another function's `jr ra` is
    not reproducible by widening: N64Recomp models the delay slot as part of the
    branch, so a goto into it has no label to land on. But the nop does nothing
    and execution falls straight through into the next function, so the branch
    is equivalent to branching to that function's start -- which N64Recomp
    *does* support, as a tail call. The fix is to redirect the branch itself.
    """
    addr = target
    while insns.get(addr, (None,))[0] == "nop":
        addr += 4
        if addr - target > 32:
            return None
    if addr != target and addr in starts:
        return addr
    return None


def branch_redirect(insn, branch_addr, new_target):
    """Re-encode a branch instruction word to point at `new_target`."""
    offset = (new_target - (branch_addr + 4)) // 4
    return (insn[2] & 0xFFFF0000) | (offset & 0xFFFF)


def terminated(end, insns):
    """True if the range ending at `end` ends with a return-like instruction.

    The delay slot of a `jr ra` is a nop, so the terminator is the second to
    last instruction as often as the last one.
    """
    for addr in (end - 4, end - 8):
        insn = insns.get(addr)
        if insn is not None and insn[0] in TERMINATORS:
            return True
    return False


def extend_to_terminator(end, vram, funcs, sizes, insns):
    """Push `end` forward until the range it defines actually terminates."""
    limit = vram + MAX_GROWTH
    while not terminated(end, insns) and end < limit:
        nxt = None
        for start, (nname, _norig) in funcs.items():
            if end <= start < limit and (nxt is None or start < nxt):
                nxt = start
        if nxt is None:
            break
        nname = funcs[nxt][0]
        end = nxt + sizes.get(nname, funcs[nxt][1])
    return end


def render_sizes(needed, funcs):
    """Render the function_sizes array exactly as it should appear in the TOML."""
    lines = ["function_sizes = ["]
    for name, size, orig in needed:
        vram = next(s for s, (n, _) in funcs.items() if n == name)
        lines.append(f'    {{ name = "{name}", size = 0x{size:X} }},'
                     f"  # was 0x{orig:X}, now 0x{vram:08X}..0x{vram + size:08X}")
    lines.append("]")
    return "\n".join(lines)


def branch_target(mnem, ops):
    if mnem not in BRANCHES:
        return None
    tokens = [t for t in re.split(r"[,\s]+", ops) if HEX8.match(t)]
    return int(tokens[-1], 16) if tokens else None


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    elf = sys.argv[1]
    toml_path = sys.argv[2] if len(sys.argv) > 2 else "wetrix.toml"

    funcs = parse_symbols(elf)
    insns = parse_disassembly(elf)
    starts = parse_all_symbol_addrs(elf)
    skip = skip_names()
    overrides = read_overrides(toml_path)
    print(f"{len(starts)} branchable symbol address(es), "
          f"{len(skip)} name(s) skipped, {len(overrides)} existing override(s)",
          file=sys.stderr)

    # Start from the ELF's own sizes, NOT from the overrides already in the
    # TOML. Seeding with them hides the escapes they were written to fix: a
    # target an earlier override already covered looks internal, so a re-run
    # never revisits or corrects it.
    sizes = {name: size for name, size in funcs.values()}

    def owner_end(target):
        """End of the function containing `target`, or None."""
        best = None
        for start, (name, _size) in funcs.items():
            size = sizes.get(name, 0)
            if start <= target < start + size:
                if best is None or start + size > best:
                    best = start + size
        return best

    unresolved = []
    redirects = []
    changed = True
    passes = 0
    while changed:
        changed = False
        passes += 1
        if passes > 40:
            print("fixpoint did not settle in 40 passes", file=sys.stderr)
            break
        for vram, (name, _orig) in sorted(funcs.items()):
            if name in skip:
                continue          # N64Recomp does not recompile this body
            end = vram + sizes.get(name, 0)
            addr = vram
            while addr < end:
                insn = insns.get(addr)
                addr += 4
                if insn is None:
                    continue
                target = branch_target(insn[0], insn[1])
                if target is None:
                    continue
                if vram <= target < end:
                    continue      # internal, fine
                if target in starts:
                    continue      # a real tail call, N64Recomp handles it
                redir = redirect_target(target, insns, starts)
                if redir is not None:
                    redirects.append((name, addr - 4, target, redir, insn))
                    continue
                if target < vram:
                    # Widening only grows a function forward, so a backward
                    # branch cannot be fixed this way. Adjacent functions that
                    # branch into each other are two entry points into one
                    # shared body.
                    entry = (name, vram, target)
                    if entry not in unresolved:
                        unresolved.append(entry)
                    continue
                new_end = max(target + 4, owner_end(target) or 0)
                # A widened range must end at a control-flow terminator. If the
                # last instruction is a call, the flow continues past the new
                # boundary, and N64Recomp emits a goto to an `after_N` label
                # that it never gets to define. Absorb the following function
                # until the range ends on a jr/j/eret.
                new_end = extend_to_terminator(new_end, vram, funcs, sizes, insns)
                if new_end > end:
                    if new_end - vram > MAX_GROWTH:
                        print(f"refusing to grow {name} past 0x{MAX_GROWTH:X}",
                              file=sys.stderr)
                        continue
                    sizes[name] = new_end - vram
                    end = new_end
                    changed = True

    grown = {name: size for name, size in sizes.items()
             if name in funcs.values() and funcs and size > 0}

    needed = []
    for name, size in sorted(sizes.items()):
        orig = None
        for start, (fname, fsize) in funcs.items():
            if fname == name:
                orig = fsize
                break
        if orig is not None and size != orig:
            needed.append((name, size, orig))

    if not needed and not unresolved:
        print("No escaping branches found.")
        return 0

    print(f"# {len(needed)} function(s) need widening"
          f"{f'; {len(unresolved)} cannot be fixed by widening' if unresolved else ''}")
    for name, baddr, target, new_target, insn in redirects:
        print(f"#   REDIRECT {name}: branch at 0x{baddr:08X} points at 0x{target:08X},"
              f" a nop that falls into 0x{new_target:08X}")
        print(f"#       patch value = 0x{branch_redirect(insn, baddr, new_target):08X}")
    if redirects:
        print("#")
    for name, vram, target in unresolved:
        print(f"#   UNRESOLVABLE {name}+backward at 0x{vram:08X} -> 0x{target:08X}"
              f"  (target is before the function start)")
    print("#")

    block = render_sizes(needed, funcs)
    print(block)

    # With --write the computed block replaces the one in the TOML, so the tool
    # is the single source of truth for the overrides instead of them being
    # pasted by hand and drifting.
    if "--write" in sys.argv:
        path = Path(toml_path)
        text = path.read_text(errors="replace")
        new_text, count = re.subn(r"function_sizes = \[.*?\n\]", block, text,
                                  count=1, flags=re.S)
        if count == 0:
            print(f"no function_sizes block found in {toml_path}", file=sys.stderr)
            return 1
        path.write_text(new_text)
        print(f"wrote {len(needed)} override(s) to {toml_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
