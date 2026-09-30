#!/usr/bin/env python3
"""Find hardware MMIO accesses inside functions N64Recomp recompiled.

The recompiled code addresses memory the same way the ROM did -- through the
MEM_* macros, which translate a KSEG0 address into an offset from rdram. That
translation only works for memory. An access to the hardware register space is
therefore not "unsupported", it is *out of bounds*: the offset lands past the end
of the 8MB rdram allocation and the process takes an access violation.

This is not a Wetrix-specific problem, it is the standard hazard of recompiling a
ROM whose libultra functions have not all been identified. N64Recomp recognises
libultra by *name*: anything on its reimplemented_funcs or ignored_funcs list has
its ROM body dropped in favour of a host implementation, which is why the
project's own `cache` and COP0 handling worked. A function still called
`func_8005AF00` gets recompiled instruction by instruction, MMIO and all.

So the useful question is not "which instruction crashed" but "how many
recompiled functions touch hardware". This answers it.

Method, and why it is a text scan rather than a disassembler:

  * N64Recomp emits one comment per MIPS instruction, followed by the C that
    implements it:

        // 0x8005AF24: lui         $t2, 0xA430
        ctx->r10 = S32(0XA430 << 16);

    The comment supplies the vram and mnemonic; the statement is what the
    constant has to be read from. The two do not share a register namespace --
    the comment says $t2 and the statement says ctx->r10 -- so mixing them is a
    reliable way to match nothing at all.
  * An MMIO address is a high half in 0xA4..0xA8 (SP, DP, MI, VI, AI, PI, RI, SI
    and beyond). KSEG1 RDRAM (0xA0000000-0xA3FFFFFF) is excluded: that is
    ordinary memory through an uncached alias and the runtime resolves it.
  * A constant only matters if the register it was loaded into is the *address*
    of a MEM_ access, so each statement's registers are tracked and the MEM_
    call's arguments are checked.

Pass `--elf build/wetrix.elf` to annotate every site with whether the function
containing it is reachable from the ROM's entrypoint. That is the difference
between a crash and a curiosity: a widened range can pull a neighbour's
hardware writes into a function nobody calls, and dead code cannot fault.

Usage:
    python tools/find_mmio_sites.py build/recomp [--elf build/wetrix.elf]
"""

import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

FUNC_RE = re.compile(r"^RECOMP_FUNC\s+void\s+(\w+)\s*\(")
COMMENT_RE = re.compile(r"//\s*(0x[0-9A-Fa-f]+):\s*(\S+)")
# The C line N64Recomp emits for `lui`, e.g. ctx->r10 = S32(0XA430 << 16);
LUI_RE = re.compile(r"ctx->(r\d+)\s*=\s*S32\(\s*0[xX]([0-9A-Fa-f]+)\s*<<\s*16")
ASSIGN_RE = re.compile(r"ctx->(r\d+)\s*=(?!=)")
MEM_RE = re.compile(r"MEM_\w+\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)")

MMIO_HIGH_MIN = 0xA400
MMIO_HIGH_MAX = 0xA9FF


def is_mmio_high(high):
    return MMIO_HIGH_MIN <= high <= MMIO_HIGH_MAX


def scan_file(path):
    """Return (function, function_vram, vram, mnemonic, high) tuples."""
    sites = []

    function = None
    function_vram = None
    # register -> high half, cleared whenever the register is assigned anything
    # else. Good enough because the generated code assigns immediately before
    # using, and it cannot produce false positives from a stale value.
    constants = {}

    last_vram = None
    last_mnemonic = None

    for line in path.read_text(errors="replace").splitlines():
        func_match = FUNC_RE.match(line)
        if func_match:
            function = func_match.group(1)
            function_vram = None
            constants = {}
            continue

        if line.lstrip().startswith("//"):
            comment_match = COMMENT_RE.search(line)
            if comment_match:
                last_vram, last_mnemonic = comment_match.groups()
                if function_vram is None:
                    function_vram = last_vram
            continue

        if not line.strip():
            continue

        lui_match = LUI_RE.search(line)
        if lui_match:
            register, immediate = lui_match.groups()
            high = int(immediate, 16) & 0xFFFF
            if is_mmio_high(high):
                constants[register] = high
            else:
                constants.pop(register, None)
            continue

        mem_match = MEM_RE.search(line)
        if mem_match:
            # One argument is the address register, the other is the immediate
            # offset. Whichever is a ctx->rN is the address; the other is what
            # gets added to it, so the two together give the register being hit.
            register = None
            offset = 0
            for argument in mem_match.groups():
                argument = argument.strip()
                register_match = re.fullmatch(r"ctx->(r\d+)", argument)
                if register_match:
                    register = register_match.group(1)
                else:
                    try:
                        offset = int(argument, 16)
                    except ValueError:
                        offset = 0

            if register is not None and register in constants:
                high = constants[register]
                sites.append(
                    (
                        function,
                        function_vram,
                        last_vram,
                        last_mnemonic,
                        high,
                        high * 0x10000 + offset,
                    )
                )
            continue

        # Any other assignment clobbers the register's known constant.
        for register in ASSIGN_RE.findall(line):
            constants.pop(register, None)

    return sites


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    root = Path(args[0] if args else "build/recomp")
    files = sorted(root.glob("funcs_*.c"))
    if not files:
        print(f"no funcs_*.c under {root}", file=sys.stderr)
        return 1

    # Whether each function is reachable, so dead code is reported separately.
    live = None
    if "--elf" in sys.argv:
        from reachability import reachable

        seen, _starts, names, _ref = reachable(sys.argv[sys.argv.index("--elf") + 1])
        live = {names[a] for a in seen if a in names}

    by_function = defaultdict(list)
    for path in files:
        for site in scan_file(path):
            by_function[site[0]].append(site[1:])

    def is_live(name):
        return True if live is None else name in live

    total = sum(len(v) for v in by_function.values())
    live_count = sum(len(v) for n, v in by_function.items() if is_live(n))
    header = f"{total} MMIO access sites in {len(by_function)} recompiled functions"
    if live is not None:
        header += f" -- {live_count} in reachable code"
    print(header + "\n")

    def sort_key(item):
        name, sites = item
        return (not is_live(name), int(sites[0][0] or "0", 16))

    for name, sites in sorted(by_function.items(), key=sort_key):
        vram = sites[0][0] or "?"
        tag = "" if live is None else ("LIVE" if is_live(name) else "dead")
        print(f"{name}  (at {vram})  -- {len(sites)} site(s)  {tag}".rstrip())
        for _, site_vram, mnemonic, high, address in sites:
            print(f"    {site_vram}  {mnemonic:<8} 0x{address:08X}")
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
