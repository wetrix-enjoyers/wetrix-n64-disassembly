#!/usr/bin/env python3
"""Resync splat's analysis of the ROM's code segment.

splat hands a subsegment to spimdisasm as one block and disassembles it
linearly. When the block is large enough, that linear pass derails somewhere
inside it: spimdisasm stops recognising function starts and instead folds whole
runs of functions into the extent of whichever function it was inside when it
lost the thread. The bytes stay correct -- the ELF still reassembles
byte-for-byte -- but the *map* is wrong, and the map is the deliverable: a
swallowed function has no symbol, so N64Recomp never recompiles it and a call
through a function pointer has nothing to resolve to.

The derail is invisible from the outside except through its symptom, and the
symptom is detectable without any reference map: a swallowed function's extent
contains instructions that its own entry cannot reach. Control flow inside a
single MIPS function cannot leave unreachable code behind, so any function whose
extent holds an unreachable instruction is two or more functions fused together.

This walks each function's control flow from its entry and reports the fusions.

It does NOT yet know where the code may safely be cut. A fusion says where the
map is wrong; it does not say that the fused function's own start is a boundary
splat can restart at, and it usually is not. A subsegment must start 8-byte
aligned (the segment's subalign, or splat pads it and every later address
shifts), and even then cutting mid-stream changes how splat reads the bytes
around the cut rather than merely resynchronising it. Measured on this ROM:

    lean config                                 642 functions, reassembles
    lean + 0x10DC0                              996 functions, reassembles
    lean + the 0x113F4 fusion (first reported)  988 functions, DOES NOT
    lean + 192 fusion-derived cuts              979 functions, DOES NOT
    lean + the 8 library boundaries             997 functions, reassembles

So the output of this tool is evidence, not a patch. The resync points in
wetrix.yaml were chosen from it and each verified by rebuilding the ELF and
running tools/verify_elf.py; that verification is the gate, not this analysis.
Until the safe-cut-point criterion is derived (a cut is safe when it leaves the
bytes splat emits for every address unchanged), writing is behind --apply.

Usage:
    python tools/split_code_units.py            # report; change nothing
    python tools/split_code_units.py --apply    # add the reported cuts to wetrix.yaml
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path.cwd()
YAML_PATH = ROOT / "wetrix.yaml"
ROM_PATH = ROOT / "baserom.z64"
ASM_DIR = ROOT / "asm"

# A subsegment this many bytes or longer is worth splitting if it fuses
# functions. Anything shorter stays as it is: the point is to give spimdisasm a
# fresh start, not to rebuild the split by hand.
MAX_ITERATIONS = 12

# ---------------------------------------------------------------- MIPS decoding
#
# Only the control-flow class of an instruction matters here, so the opcode and
# the `special` function field are read directly. No disassembler is involved.

OP_J, OP_JAL = 0x02, 0x03
OP_BEQ, OP_BNE, OP_BLEZ, OP_BGTZ = 0x04, 0x05, 0x06, 0x07
OP_REGIMM = 0x01
OP_BEQL, OP_BNEL, OP_BLEZL, OP_BGTZL = 0x14, 0x15, 0x16, 0x17
OP_COP0, OP_COP1, OP_COP2 = 0x10, 0x11, 0x12

FN_JR, FN_JALR = 0x08, 0x09
RS_RA = 31

BRANCHES = {OP_BEQ, OP_BNE, OP_BLEZ, OP_BGTZ, OP_REGIMM,
            OP_BEQL, OP_BNEL, OP_BLEZL, OP_BGTZL}


def edges(word: int, pc: int) -> tuple[list[int], list[int]]:
    """Where control goes from `pc`, as (keep walking from, executes then stops).

    MIPS delay slots are the reason for two lists. The instruction after a
    branch or jump always executes, but it is only a stepping stone for a
    *conditional* branch -- after an unconditional jump it is a dead end, and
    treating it as a stepping stone would walk straight into the next function
    and hide exactly the fusions this is looking for.
    """
    op = word >> 26
    if op == OP_JAL:
        return [pc + 4], []                      # returns, so execution resumes
    if op == OP_J:
        target = ((pc + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
        return [target], [pc + 4]
    if op in BRANCHES:
        off = word & 0xFFFF
        if off & 0x8000:
            off -= 0x10000
        # Not taken falls through past the delay slot; walking from the delay
        # slot covers that, since it continues on its own.
        return [pc + 4, pc + 4 + (off << 2)], []
    if op == 0 and (word & 0x3F) in (FN_JR, FN_JALR):
        # `jr $ra` is a return and `jalr` returns too; any other register is an
        # indirect target, reachable through a jump table this block refers to
        # and seeded as an extra root -- not something to walk blindly.
        return [], [pc + 4]
    return [pc + 4], []


# --------------------------------------------------------------------- asm IO

LABEL_LINE = re.compile(r"^([A-Za-z_.$][\w.$]*):\s*$")
JUMP_TABLE_REF = re.compile(r"\b(jtbl_[A-Za-z0-9_]+)\b")
ENT_LINE = re.compile(r"^\.ent\s+(\S+)")
END_LINE = re.compile(r"^\.end\s+(\S+)")
DATA_DIRECTIVES = {
    ".word": 4, ".long": 4,
    ".float": 4,
    ".double": 8,
    ".half": 2, ".short": 2,
    ".byte": 1,
}
SPACE_DIRECTIVES = {".space": 1, ".skip": 1, ".zero": 1}
STRING_DIRECTIVES = {".ascii": 1, ".asciz": 1, ".string": 1}


def parse_subsegments(text: str) -> tuple[re.Match, list[list]]:
    """Return the main segment's subsegments block and its entries.

    Entries keep their raw form (`[0x1040, rodata]`) so a rewrite preserves any
    type annotations already there.
    """
    m = re.search(
        r"(  - name: main\n(?:.*\n)*?    subsegments:\n)"
        r"((?:[ \t]*- \[[^\]]*\][ \t]*\n|[ \t]*#[^\n]*\n|\n)*)",
        text,
    )
    if m is None:
        raise SystemExit("wetrix.yaml: could not find the `main` segment's subsegments block")
    entries = []
    for line in m.group(2).splitlines():
        s = re.match(r"^\s*- \[([^\]]*)\]\s*$", line)
        if s:
            entries.append(s.group(1))
    if not entries:
        raise SystemExit("wetrix.yaml: the `main` segment has no subsegments")
    return m, entries


def entry_addr(entry: str) -> int:
    return int(entry.split(",")[0].strip(), 16)


def entry_type(entry: str) -> str:
    return entry.split(",")[1].strip()


def render(entries: list[tuple[int, str]]) -> str:
    return "".join(f"      - [0x{a:X}, {t}]\n" for a, t in sorted(entries))


# --------------------------------------------------------- fusion detection

def line_size(line: str, addr: int) -> int:
    """Bytes of data/code a single assembly line contributes.

    Comments are cut first: splat annotates `.word` lines with the disassembly
    it decoded (`# break 1, 2`), and those commas are not list separators.
    """
    line = line.split("#", 1)[0].strip()
    if not line:
        return 0
    if not line.startswith("."):
        return 4 if not LABEL_LINE.match(line) else 0
    parts = line.split(None, 1)
    name = parts[0]
    arg = parts[1].strip() if len(parts) > 1 else ""
    if name in DATA_DIRECTIVES:
        # Splat emits one value per directive; count the list form too.
        n = 0
        depth = 0
        for ch in arg:
            if ch == "," and depth == 0:
                n += 1
            depth += (ch == "(") - (ch == ")")
        return DATA_DIRECTIVES[name] * (n + 1)
    if name in SPACE_DIRECTIVES:
        try:
            return int(arg, 0)
        except ValueError:
            return 0
    if name in STRING_DIRECTIVES:
        # Crude, but only used as a cross-check on names we do not emit.
        return len(arg) - arg.count('"') + (1 if name != ".ascii" else 0)
    if name in (".align",) or name in (".balign",):
        try:
            n = int(arg, 0)
        except ValueError:
            return 0
        boundary = (1 << n) if name == ".align" else n
        return (-addr) % boundary if boundary else 0
    return 0


def read_split(asm_dir: Path, entries: list[tuple[int, str]], seg_rom: int,
               seg_vram: int):
    """Return (extents, labels) for the split on disk.

    `extents` is (vram, byte_length, name, jump_table_refs) for every
    `.ent`/`.end` block; `labels` maps every label the split declares to its
    address, which is what makes jump tables resolvable -- a `jtbl_` label lives
    in the read-only data and its entries are the case addresses in the code.

    Addresses are accumulated by counting every line's bytes, and each file's
    total is checked against the subsegment extent the config declares. If the
    counts drift -- a directive this does not know, or a file that does not
    start where its name says -- that check fails rather than producing a
    plausible-looking wrong answer.
    """
    starts = sorted(a for a, _ in entries)
    seg_end = max(starts)
    out: list[tuple[int, int, str, set[str]]] = []
    labels: dict[str, int] = {}
    for path in sorted(asm_dir.rglob("*.s")):
        head = path.name.split(".")[0]
        try:
            base_rom = int(head, 16)
        except ValueError:
            continue
        if not (seg_rom <= base_rom < seg_end):
            continue          # another segment's output, e.g. the entry stub
        if base_rom not in starts:
            raise SystemExit(
                f"{path}: rom 0x{base_rom:X} is not a subsegment in wetrix.yaml. "
                f"This is stale output from a different config; delete asm/ and "
                f"re-run splat."
            )
        expected = next((a for a in starts if a > base_rom), seg_end) - base_rom
        base_vram = base_rom + (seg_vram - seg_rom)
        addr = base_vram
        block_start = None
        name = None
        refs: set[str] = set()
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", ".set", ".section", ".include")):
                continue
            lab = LABEL_LINE.match(line)
            if lab:
                labels[lab.group(1)[:-1]] = addr
                if block_start is not None:
                    refs.update(JUMP_TABLE_REF.findall(line))
                continue
            e = ENT_LINE.match(line)
            if e:
                block_start, name, refs = addr, e.group(1), set()
                continue
            if END_LINE.match(line):
                if block_start is not None:
                    out.append((block_start, addr - block_start, name, refs))
                block_start = None
                continue
            if block_start is not None:
                refs.update(JUMP_TABLE_REF.findall(line))
            addr += line_size(line, addr)
        produced = addr - base_vram
        if produced != expected:
            raise SystemExit(
                f"{path}: walked {produced:#x} bytes but the config gives this "
                f"subsegment {expected:#x} (rom 0x{base_rom:X}). A directive is "
                f"not being counted; refusing to guess."
            )
    return out, labels


MAX_JUMP_TABLE_ENTRIES = 512


def jump_table_targets(refs, labels, rom: bytes, seg_vram: int, seg_rom: int,
                       code_lo: int, code_hi: int) -> set[int]:
    """Case addresses of every jump table a block refers to.

    The entries are read straight out of the ROM and kept while they stay inside
    the code segment, which is what bounds the table -- the first word that is
    not a code address is the next thing in `.rodata`.
    """
    targets: set[int] = set()
    for name in refs:
        base = labels.get(name)
        if base is None:
            continue
        for i in range(MAX_JUMP_TABLE_ENTRIES):
            off = base - seg_vram + seg_rom + 4 * i
            if off < 0 or off + 4 > len(rom):
                break
            word = int.from_bytes(rom[off:off + 4], "big")
            if not (code_lo <= word < code_hi):
                break
            targets.add(word)
    return targets


def fused_functions(extents, labels, rom: bytes, seg_vram: int, seg_rom: int,
                    code_lo: int, code_hi: int) -> list[int]:
    """Function starts whose extent contains instructions the entry cannot reach.

    Only direct control flow is followed, so a block reached solely through a
    jump table would look unreachable -- which is why the table targets are
    seeded as extra roots rather than the analysis giving up on `jr $t0`.
    """
    def load(vram: int) -> int:
        off = vram - seg_vram + seg_rom
        return int.from_bytes(rom[off:off + 4], "big")

    bad = []
    for vram, size, name, refs in extents:
        if size < 8:
            continue
        count = size // 4
        roots = [vram]
        roots.extend(sorted(jump_table_targets(refs, labels, rom, seg_vram, seg_rom,
                                               code_lo, code_hi)))
        seen = set()
        stack = roots
        while stack:
            pc = stack.pop()
            while vram <= pc < vram + size and pc not in seen:
                seen.add(pc)
                walk, leaf = edges(load(pc), pc)
                for a in leaf:
                    if vram <= a < vram + size:
                        seen.add(a)
                if not walk:
                    break
                stack.extend(a for a in walk[1:] if vram <= a < vram + size)
                pc = walk[0]
        if len(seen) != count:
            bad.append(vram)
    return bad


# ------------------------------------------------------------------ driving it

def run_splat() -> None:
    # splat writes the files it is told to and leaves everything else where it
    # was, so output from a previous config survives and gets analysed as if it
    # belonged to the new one.
    shutil.rmtree(ASM_DIR, ignore_errors=True)
    r = subprocess.run([sys.executable, "-m", "splat", "split", "wetrix.yaml"],
                       cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write(r.stdout[-4000:] + r.stderr[-4000:])
        raise SystemExit("splat split failed")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true",
                    help="analyse the split already on disk; do not run splat")
    ap.add_argument("--apply", action="store_true",
                    help="write the reported resync points into wetrix.yaml (verify the ELF after)")
    args = ap.parse_args()

    doc = yaml.safe_load(YAML_PATH.read_text())
    main_seg = next(s for s in doc["segments"] if s.get("name") == "main")
    seg_rom, seg_vram = main_seg["start"], main_seg["vram"]

    rom = ROM_PATH.read_bytes()
    text = YAML_PATH.read_text()
    m, raw_entries = parse_subsegments(text)
    entries = [(entry_addr(e), entry_type(e)) for e in raw_entries]

    if not args.check:
        run_splat()

    previous: list[int] = []
    for iteration in range(1, MAX_ITERATIONS + 1):
        extents, labels = read_split(ASM_DIR, entries, seg_rom, seg_vram)
        code = sorted(a for a, t in entries if t == "asm")
        rom_lo = code[0]
        rom_hi = max(a for a, t in entries if t in ("asm", "data"))
        vram_of = lambda a: a - seg_rom + seg_vram          # noqa: E731
        fused = fused_functions(extents, labels, rom, seg_vram, seg_rom,
                                vram_of(rom_lo), vram_of(rom_hi))
        # Only fusion points inside the code region can be resync subsegments.
        fused = [a for a in fused if vram_of(rom_lo) < a <= vram_of(rom_hi)]
        # The `main` segment is declared align: 8 / subalign: 8, and splat pads
        # a subsegment up to that alignment. A resync point that is only
        # 4-aligned therefore shifts every address after it and the ELF stops
        # reassembling byte-for-byte -- silently, since the split still looks
        # sane. Such a point cannot be split on; the derail there has to be
        # handled by whatever resync lands before it.
        misaligned = [a for a in fused if (a - seg_vram + seg_rom) % 8]
        fused = [a for a in fused if not (a - seg_vram + seg_rom) % 8]
        if fused == previous:
            # Splitting there did not change the analysis, so these are extents
            # whose unreachable code is reached some way the static walk cannot
            # see -- jump tables built at run time, or code entered mid-function
            # by a computed branch. They are not evidence of a derail.
            print(f"no further progress: {len(fused)} extents the walk cannot "
                  f"explain, treated as false positives")
            print("code segment resolves as far as this analysis can tell")
            break
        previous = fused
        print(f"round {iteration}: {len(extents)} functions, "
              f"{len(fused)} fused (derailed) functions")

        if not fused:
            print("code segment resolves cleanly")
            break
        for a in fused[:8]:
            print(f"    fusion at 0x{a:08X}  (rom 0x{a - seg_vram + seg_rom:X})")
        if len(fused) > 8:
            print(f"    ... and {len(fused) - 8} more")
        if misaligned:
            print(f"    {len(misaligned)} more are not 8-byte aligned and cannot be split")

        if args.check:
            break
        if not args.apply:
            print(f"    {len(fused)} resync subsegments would be added; "
                  f"pass --apply to write them, then rebuild and run "
                  f"tools/verify_elf.py before keeping them")
            break

        # The analysis works in vram (that is what the instruction stream uses);
        # the config's subsegments are rom offsets.
        entries = sorted(set(entries) | {(a - seg_vram + seg_rom, "asm") for a in fused})
        text = YAML_PATH.read_text()
        m, _ = parse_subsegments(text)
        text = text[:m.start(2)] + render(entries) + text[m.end(2):]
        YAML_PATH.write_text(text)
        run_splat()
    else:
        print(f"stopped after {MAX_ITERATIONS} rounds without converging", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
