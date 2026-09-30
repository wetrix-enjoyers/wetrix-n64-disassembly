# Wetrix (N64) — disassembly

A split-and-name project for the US release of Wetrix (1998). Its output is a
description of how the ROM's code is laid out, which is what a recompilation
port needs as its input. That is a separate project beside this one:
`wetrix-n64-recompilation`, whose `tools/regen.py` runs this project's build.

**You supply your own ROM.** Nothing in this repository contains, or can
produce, any part of the game.

## What this produces, and why

N64Recomp does not want the game's source. It reads instruction bytes directly
out of `baserom.z64`. What it cannot get from the ROM is the shape of the code:
where each function starts, how long it is, and what things are called. A ROM is
a formless blob and nothing in it marks where one function ends and the next
begins.

Producing that map is this project's entire job.

The map is written out as a MIPS ELF, `build/wetrix.elf`. The ELF is a carrier,
not code: N64Recomp reads symbol names, addresses and sizes out of it, and takes
nothing else. Every byte it actually recompiles comes from your own ROM, which
is why this repository can be public and the game can't.

## What you need

- Your own US Wetrix ROM, placed at the repo root as `baserom.z64` (8 MB)
- Python 3.10 or newer, with a virtualenv
- Docker, for GNU MIPS binutils

## Getting an ELF

### 1. Python environment

```
python3 -m venv venv
venv/bin/pip install -r requirements.txt          # Windows: venv/Scripts/pip
```

The versions are pinned exactly, and deliberately. A new splat release changes
how it labels segments, and that changes every generated function name — which
the port's configuration refers to by name.

### 2. MIPS toolchain container

splat's output is written for GNU `as`, and there is no native Windows build of
`binutils-mips-linux-gnu`, so we assemble in a container:

```
docker build -t wetrix-mips -f tools/Dockerfile.mips tools
```

### 3. Split the ROM

```
venv/bin/splat split wetrix.yaml
```

Reads `baserom.z64` and writes `asm/*.s`, one file per segment, plus the link
script `build/wetrix.ld`.

### 4. Build the ELF

```
docker run --rm -v ".:/work" -w /work wetrix-mips python3 tools/build_elf.py
```

Output: `build/wetrix.elf`.

### 5. Check it

```
docker run --rm -v ".:/work" -w /work wetrix-mips python3 tools/verify_elf.py
```

The link script places every section with `AT()`, so each output section's load
address is its offset in the ROM. That makes a direct comparison possible, and a
clean result means the reassembly reproduces the original ROM byte for byte —
a much stronger claim than "the link succeeded", and it is what makes the
function boundaries N64Recomp reads trustworthy.

### All at once

```
python tools/build.py [--force]
```

Runs steps 1 to 5, each only when a hash of its inputs differs from the last run
(venv: `requirements.txt`; split: `wetrix.yaml`, `config/`, `reloc_addrs.txt`, `baserom.z64`,
`requirements.txt`; ELF: what the split wrote, `include/`, and the two tools),
and builds the container image if it is missing. The records are
`build/.split.inputs` and `build/.elf.inputs`.

When it fails, `find_drift.py` walks the same sections and produces the punch
list: what diverged, and where.

## The diagnostics in `tools/`

The rest of the tools exist because *recompiling* a ROM is not the same as
disassembling one, and this ROM goes wrong in four specific ways. They read the
ROM and predict what the recompiler will do with it; their findings become the
port's configuration, which makes them the seam between the two projects.

- **`find_truncated.py`** — functions whose recompiled body was silently cut
  short. When splat splits a real function in two, because the ROM jumps into
  the middle of its body, the outer symbol keeps only the prologue. A prologue
  contains no `jr $ra`, so the generated C falls off its own end and the
  function does nothing. Not a compile error and not a link error, so the only
  way to catch it is to look at the bytes.
- **`find_branch_escapes.py`** — branches that leave their own function. `gcc`
  cross-jumps identical code tails, so a function ends by branching forward
  into the epilogue of the *next* function. N64Recomp can only branch within a
  function or exactly onto another function's start.
- **`find_mmio_sites.py`** — hardware register accesses inside recompiled code.
  The `MEM_*` macros translate a KSEG0 address into an offset from rdram, which
  is only valid for memory; a hardware access lands past the end of the 8 MB
  allocation and takes an access violation.
- **`find_reachable.py`** — which of the ELF's function symbols the ROM can
  actually reach. Splat is generous about creating `func_XXXXXXXX` names,
  including boundaries that no `jal` and no branch ever targets.
- **`reachability.py`** — the shared call-graph engine, kept separate because
  `find_reachable.py` reports its answer and `find_mmio_sites.py` uses it to
  tell a live hardware access from one sitting in dead code.
- **`find_hardware_funcs.py`** — every still-unnamed function that touches
  hardware, with the block it addresses (`lui 0xA460` is the parallel interface,
  `0xA440` video, `0xA450` audio, `0xA404`/`0xA410` the RSP) and the COP0
  register it moves. Those two facts are the function's name: a 12-byte
  `mfc0 r2, cop0[12]` is `__osGetSR` and there is nothing else it could be.
  Reads the ELF and the ROM, so it works before the recompile is clean — which
  it cannot be until the names exist. 55 functions here, against the 242 entries
  the inherited table carried.
- **`split_code_units.py`** — where splat's linear analysis of the code segment
  derailed, and how badly. A swallowed function's extent contains instructions
  its own entry cannot reach, which is what it looks for; the numbers are in the
  `subsegments` comment in `wetrix.yaml`. It reports rather than patches, because
  where the map is wrong is not the same question as where the segment may
  safely be cut: of 192 fusion-derived cuts, none that were tried kept the ELF
  reassembling, while the eight SDK code-unit boundaries did.
- **`find_ucode_targets.py`** — the audio microcode's jump-table targets. They
  exist only as data, and RSPRecomp derives its indirect branches from the
  instruction stream, so it cannot find them on its own.
- **`rom_hash.c`** — the hash librecomp compares a ROM against. The port needs
  this value for its `GameEntry`, and a wrong one means the ROM is silently
  rejected and the game never starts. Needs xxHash from a N64ModernRuntime
  checkout to build.

## Status

The workflow above runs. `wetrix.yaml` in this repository is generated from the
ROM rather than inherited, and the ELF it produces verifies byte-for-byte
faithful to `baserom.z64` — all 8,388,608 bytes, zero mismatches.

The split now also carries the ROM's function boundaries: 997 of them, where
treating the code segment as a single block yields 642. The difference is not
cosmetic. splat analyses a code subsegment linearly and, given one 350 KB block,
derails partway through and folds runs of functions into a neighbour's extent —
`func_80010D10` comes out 1,120 bytes where the ROM has eight functions in that
span. A folded function has no symbol, so N64Recomp never recompiles it and
nothing can resolve a pointer to it. Cutting the code segment at the boundaries
between the SDK's code units repairs it, and those cuts are the load-bearing
part of the `subsegments` list in `wetrix.yaml`, with the measurements recorded
next to them.

Against the port's own N64Recomp configuration this map recompiles 3,279
functions and no longer aborts. What is still missing is the symbol *names*. A
split with no names reassembles correctly, because names do not change bytes,
but N64Recomp decides what to hand to the runtime **by name**: `0x80060A00` is a
12-byte function in both maps, ours called `func_80060A00` — recompiled
instruction by instruction, then faulting on `mtc0 $11` — and theirs called
`__osSetCompare`, which is on N64Recomp's reimplemented list and gets the
runtime's version instead. Naming the libultra functions is the next piece of
work, and `find_hardware_funcs.py` measures what that buys: 55 functions touch
hardware, 26 of them have a name N64Recomp already provides an implementation
for, 13 more are covered by the port's own configuration, and 16 need a shim in
the port. N64Recomp models exactly one COP0 register (Status), so the rest can
only be fixed by naming them or by replacing them — leaving them to recompile is
not an option.

## Licence

MIT (`LICENSE`, Copyright (c) 2026 Wetrix Enjoyers). That covers the tools and configuration in
this repository. The game is not part of it: the ROM and everything derived from it
(`asm/`, `assets/`, the ELF) stay out of the repository.

`include/` is written by splat on each split and is not part of the repository; see `NOTICE.md`.
