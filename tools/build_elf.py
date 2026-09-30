#!/usr/bin/env python3
"""Assemble the Wetrix splat split into a MIPS ELF for N64Recomp.

Run inside the toolchain container:

    docker run --rm -v "$PWD:/work" -w /work wetrix-mips python3 tools/build_elf.py

The ELF produced here carries symbols, sizes and addresses only. N64Recomp
reads instruction bytes straight out of baserom.z64 and uses the ELF purely as
a metadata map (symbol names, function boundaries, relocations), so this does
not need to reproduce the ROM byte-for-byte -- it needs every function boundary
to be correct and every referenced symbol to resolve to the right address.

Getting splat's `asm`-style output through modern GNU as needs four fixes,
each documented where it is applied:

  1. `.type @function` restoration (splat's macro.inc cannot override `.globl`)
  2. the two-operand `div`/`divu`/`ddiv`/`ddivu` macro form
  3. an object for the trailing `bss` subsegment, which splat references in the
     link script but emits no source for
  4. absolute definitions for the symbols splat leaves undefined
"""

from __future__ import annotations

import concurrent.futures
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

AS = "mips-linux-gnu-as"
LD = "mips-linux-gnu-ld"
READELF = "mips-linux-gnu-readelf"
NM = "mips-linux-gnu-nm"
# -march=mips3 because the CPU is an R4300i (64-bit MIPS III); the default
# mips1 target rejects `daddiu`, `bltzl`, `beql` and `.set gp=64`.
# NOTE: there is no as flag to disable the implicit divide-by-zero expansion
# (`-mno-check-zero-division` is not recognised by this binutils), so the
# transform below rewrites the macro forms instead.
ASFLAGS = ["-march=mips3", "-I", "include"]

ROOT = Path.cwd()
SRC = ROOT / "asm"
GEN = ROOT / "build" / "asm_src"
OBJ = ROOT / "build" / "asm"
STUBS = ROOT / "build" / "gen_assets"
ASSET_OBJ = ROOT / "build" / "assets"
LD_SCRIPT = ROOT / "build" / "wetrix.ld"
MAP = ROOT / "build" / "wetrix.map"
ELF = ROOT / "build" / "wetrix.elf"

ASSETS = ("ipl3", "rom_data", "sound_things")

RE_BSS_SIZE = re.compile(r"^\s*bss_size:\s*(0x[0-9A-Fa-f]+)", re.M)
RE_LD_OBJ = re.compile(r"(build/asm/[A-Za-z0-9_/.-]+\.o)")
RE_SYM_DEF = re.compile(r"^([A-Za-z0-9_.$]+)\s*=\s*(0x[0-9A-Fa-f]+)")
RE_GLOBL = re.compile(r"^(\s*)\.globl\s+(\S+)\s*$")
RE_ENT = re.compile(r"^\s*\.ent\s+(\S+)\s*$")
RE_DIV2 = re.compile(r"^(\s*(?:ddivu|ddiv|divu|div)\s+)(\$\S+?),\s*(\$\S+?)\s*$")
RE_UNDEF = re.compile(r"undefined reference to .([A-Za-z0-9_.$]+)")

# splat names symbols it cannot identify after their VRAM address, including
# local labels (`.L8005BFDC`) and jump tables, so the address is recoverable
# straight from the name.
RE_NAMED_ADDR = re.compile(r"^(?:D_|func_|jtbl_|\.L)([0-9A-Fa-f]{8})$")


def transform(text: str) -> str:
    """Rewrite the two-operand divide macros, and restore `.type`."""

    # `divu $rs, $rt` assembles to four instructions (a synthesised
    # divide-by-zero check) while `divu $zero, $rs, $rt` is the single hardware
    # instruction the ROM actually contains.
    lines = text.splitlines()
    out: list[str] = []

    for i, line in enumerate(lines):
        m = RE_DIV2.match(line)
        if m:
            line = f"{m.group(1)}$zero, {m.group(2)}, {m.group(3)}"
        out.append(line)

        g = RE_GLOBL.match(line)
        if g and i + 1 < len(lines):
            e = RE_ENT.match(lines[i + 1])
            if e and e.group(1) == g.group(2):
                out.append(f"{g.group(1)}.type {g.group(2)}, @function")

    return "\n".join(out) + "\n"


def assemble_sources() -> list[Path]:
    if not SRC.is_dir() or not LD_SCRIPT.is_file():
        sys.exit("error: asm/ or build/wetrix.ld missing -- run splat first")

    for d in (GEN, OBJ, STUBS, ASSET_OBJ):
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True, exist_ok=True)

    sources: list[Path] = []
    for src in sorted(SRC.rglob("*.s")):
        dest = GEN / src.relative_to(SRC)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(transform(src.read_text(encoding="utf-8", errors="replace")))
        sources.append(dest)

    def run(src: Path) -> tuple[Path, subprocess.CompletedProcess]:
        obj = OBJ / src.relative_to(GEN).with_suffix(".o")
        obj.parent.mkdir(parents=True, exist_ok=True)
        return src, subprocess.run(
            [AS, *ASFLAGS, "-o", str(obj), str(src)], capture_output=True, text=True
        )

    failures: list[tuple[Path, str]] = []

    # One `as` per core is right on a normal filesystem, but this is usually run
    # inside a container on a Windows bind mount, where every assembler process
    # reads its source and writes its object across the mount boundary. Past a
    # handful of writers that path serialises and the run takes tens of minutes
    # instead of seconds, so the count is tunable:
    #
    #   BUILD_ELF_JOBS=8 docker run ... python3 tools/build_elf.py
    jobs = int(os.environ.get("BUILD_ELF_JOBS", os.cpu_count() or 4))
    print(f"assembling {len(sources)} files with {jobs} workers")

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        for src, proc in pool.map(run, sources):
            if proc.returncode != 0:
                failures.append((src, proc.stderr))

    if failures:
        print(f"error: {len(failures)} of {len(sources)} files failed to assemble")
        for src, err in failures[:5]:
            print(f"\n--- {src} ---\n{err[:1200]}")
        sys.exit(1)

    print(f"assembled {len(sources)} objects")
    return sources


def assemble_stub(name: str, body: str) -> Path:
    """Assemble a synthetic .s snippet into build/assets/<name>.o."""
    src = STUBS / f"{name}.s"
    src.write_text(body)
    obj = ASSET_OBJ / f"{name}.o"
    proc = subprocess.run(
        [AS, *ASFLAGS, "-o", str(obj), str(src)], capture_output=True, text=True
    )
    if proc.returncode != 0:
        sys.exit(f"error: assembling {name} stub:\n{proc.stderr}")
    return obj


def wrap_assets() -> None:
    for name in ASSETS:
        blob = ROOT / "assets" / f"{name}.bin"
        if not blob.is_file():
            sys.exit(f"error: missing asset blob {blob}")
        assemble_stub(name, f'.section .data\n.incbin "assets/{name}.bin"\n')
    print(f"wrapped {len(ASSETS)} asset blobs")


def make_bss() -> None:
    """splat's link script wants an object for the trailing `bss` subsegment
    but emits no source for it, since bss has no ROM content. Without it the
    entrypoint's BSS-zeroing loop would cover a zero-length range."""
    m = RE_BSS_SIZE.search((ROOT / "wetrix.yaml").read_text())
    if not m:
        sys.exit("error: no bss_size in wetrix.yaml")
    size = int(m.group(1), 16)

    for rel in sorted(set(RE_LD_OBJ.findall(LD_SCRIPT.read_text()))):
        if (ROOT / rel).is_file():
            continue
        if not rel.endswith(".bss.o"):
            sys.exit(f"error: link script needs {rel} but nothing produced it")
        dst = ROOT / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        src = STUBS / f"{Path(rel).stem}.bss.s"
        src.write_text(f".section .bss\n.space {size:#x}\n")
        proc = subprocess.run(
            [AS, *ASFLAGS, "-o", str(dst), str(src)], capture_output=True, text=True
        )
        if proc.returncode != 0:
            sys.exit(f"error: assembling {rel}:\n{proc.stderr}")
        print(f"recreated {rel} ({size:#x} bytes)")


def defined_symbols(sources: list[Path]) -> set[str]:
    names = set()
    for src in sources:
        for line in src.read_text().splitlines():
            g = RE_GLOBL.match(line)
            if g:
                names.add(g.group(2))
    return names


def splat_symbol_defs(defined: set[str]) -> dict[str, int]:
    """Addresses from splat's auto symbol files, minus anything already defined.

    These are mostly bss and jump-table addresses in the low memory region that
    the disassembly references but never defines.
    """
    defs: dict[str, int] = {}
    skipped = 0
    for fname in ("undefined_funcs_auto.txt", "undefined_syms_auto.txt"):
        path = ROOT / fname
        if not path.is_file():
            continue
        for raw in path.read_text().splitlines():
            line = raw.split("//", 1)[0].strip()
            m = RE_SYM_DEF.match(line)
            if not m:
                continue
            if m.group(1) in defined:
                skipped += 1
                continue
            defs[m.group(1)] = int(m.group(2), 16)
    print(f"loaded {len(defs)} symbol addresses from splat's auto files")
    return defs


def link(defs: dict[str, int]) -> subprocess.CompletedProcess:
    # --defsym rather than an assembled object: a `NAME = value` assignment in
    # gas creates a *local* symbol that cannot satisfy cross-object references,
    # and globalizing is impossible for the `.L` labels splat emits for branch
    # targets. --defsym creates proper globals for every case.
    defsym = [f"--defsym={name}=0x{addr:08x}" for name, addr in sorted(defs.items())]
    return subprocess.run(
        [
            LD,
            "-T", str(LD_SCRIPT),
            "-e", "entrypoint",
            "-Map", str(MAP),
            "--no-warn-rwx-segments",
            "-o", str(ELF),
            *defsym,
        ],
        capture_output=True,
        text=True,
    )


def report() -> None:
    print()
    proc = subprocess.run([READELF, "-h", str(ELF)], capture_output=True, text=True)
    for line in proc.stdout.splitlines():
        if re.search(r"Entry point|Type:", line):
            print("  " + line.strip())

    proc = subprocess.run([NM, "--defined-only", str(ELF)], capture_output=True, text=True)
    lines = [l for l in proc.stdout.splitlines() if l.strip()]
    funcs = sum(1 for l in lines if re.search(r"\b[Tt]\b", l))
    print(f"  {len(lines)} defined symbols, {funcs} in .text")
    print(f"\nwrote {ELF.relative_to(ROOT)}")


def main() -> int:
    sources = assemble_sources()
    wrap_assets()
    make_bss()

    defs = splat_symbol_defs(defined_symbols(sources))

    result = link(defs)
    if result.returncode != 0:
        # Anything still unresolved gets defined from the address encoded in
        # its own name, which is exactly the address splat disassembled from.
        missing = sorted(set(RE_UNDEF.findall(result.stderr)) - set(defs))
        unhandled = [n for n in missing if not RE_NAMED_ADDR.match(n)]
        if unhandled:
            print(f"error: {len(unhandled)} undefined symbols have no derivable address")
            for name in unhandled[:20]:
                print(f"  {name}")
            return 1
        for name in missing:
            defs[name] = int(RE_NAMED_ADDR.match(name).group(1), 16)
        print(f"defined {len(missing)} more symbols from their encoded addresses")

        result = link(defs)
        if result.returncode != 0:
            print("error: link failed")
            print(result.stderr.strip()[:4000])
            return 1

    report()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
