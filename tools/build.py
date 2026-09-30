#!/usr/bin/env python3
"""Bring build/wetrix.elf up to date, doing only the steps whose inputs changed.

    python tools/build.py [--force]

Three steps, each skipped when a hash of its inputs matches the one recorded the
last time it ran:

  venv    python -m venv venv; pip install -r requirements.txt   (README, step 1)
          inputs: requirements.txt (recorded in venv/.requirements)

  split   splat split wetrix.yaml             (README, step 3)
          inputs: wetrix.yaml, config/, reloc_addrs.txt, baserom.z64,
                  requirements.txt
  elf     tools/build_elf.py, then            (README, steps 4 and 5)
          tools/verify_elf.py, in the wetrix-mips container
          inputs: everything the split wrote (asm/, assets/, build/wetrix.ld,
                  undefined_*_auto.txt), include/, the two tools

Content hashes rather than timestamps, so a re-split that writes identical
files does not rebuild the ELF. The records are build/.split.inputs and
build/.elf.inputs; --force ignores them. The container image is built from
tools/Dockerfile.mips if it is missing.

Downstream, wetrix-n64-recompilation's tools/regen.py runs this first.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
ELF = BUILD / "wetrix.elf"
IMAGE = "wetrix-mips"
VENV = ROOT / "venv"

SPLIT_INPUTS = ["wetrix.yaml", "config", "reloc_addrs.txt", "baserom.z64", "requirements.txt"]
ELF_INPUTS = ["asm", "assets", "include", "build/wetrix.ld", "undefined_funcs_auto.txt",
              "undefined_syms_auto.txt", "tools/build_elf.py", "tools/verify_elf.py"]


def digest(names: list[str]) -> str:
    """One hash over every file under `names`, in a stable order, by path and content."""
    h = hashlib.sha256()
    for name in names:
        p = ROOT / name
        files = sorted(f for f in p.rglob("*") if f.is_file()) if p.is_dir() else [p]
        for f in files:
            h.update(f.relative_to(ROOT).as_posix().encode() + b"\0")
            h.update(f.read_bytes() if f.is_file() else b"<missing>")
            h.update(b"\0")
    return h.hexdigest()


def current(record: Path, value: str, *outputs: Path) -> bool:
    return (record.is_file() and record.read_text().strip() == value
            and all(o.exists() for o in outputs))


def run(cmd: list[str], **kw) -> None:
    print("build:", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=ROOT, check=True, **kw)


def venv_bin(name: str) -> Path:
    for p in (VENV / "Scripts" / f"{name}.exe", VENV / "bin" / name):
        if p.is_file():
            return p
    return VENV / "bin" / name


def ensure_venv(force: bool) -> None:
    """The Python environment splat runs in, pinned by requirements.txt."""
    rec = VENV / ".requirements"
    want = digest(["requirements.txt"])
    if not force and rec.is_file() and rec.read_text().strip() == want and venv_bin("splat").is_file():
        print("build: venv is current")
        return
    if not (VENV / "pyvenv.cfg").is_file():
        run([sys.executable, "-m", "venv", str(VENV)])
    run([str(venv_bin("python")), "-m", "pip", "install", "-r", "requirements.txt"])
    rec.write_text(want + "\n")


def splat() -> Path:
    return venv_bin("splat")


def docker(script: str) -> None:
    have = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True).returncode == 0
    if not have:
        run(["docker", "build", "-t", IMAGE, "-f", "tools/Dockerfile.mips", "tools"])
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    run(["docker", "run", "--rm", "-v", f"{ROOT.as_posix()}:/work", "-w", "/work",
         IMAGE, "python3", script], env=env)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--force", action="store_true", help="run every step")
    args = ap.parse_args()
    if not (ROOT / "baserom.z64").is_file():
        sys.exit("build: no baserom.z64 at the repo root (see README)")
    BUILD.mkdir(exist_ok=True)
    ensure_venv(False)

    rec = BUILD / ".split.inputs"
    h = digest(SPLIT_INPUTS)
    if args.force or not current(rec, h, ROOT / "asm", BUILD / "wetrix.ld"):
        run([str(splat()), "split", "wetrix.yaml"])
        rec.write_text(h + "\n")
    else:
        print("build: split is current")

    rec = BUILD / ".elf.inputs"
    h = digest(ELF_INPUTS)
    if args.force or not current(rec, h, ELF):
        rec.unlink(missing_ok=True)  # a failed verify must not leave the ELF looking current
        docker("tools/build_elf.py")
        docker("tools/verify_elf.py")
        rec.write_text(h + "\n")
    else:
        print("build: build/wetrix.elf is current")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as e:
        sys.exit(f"build: failed ({e.returncode}): {' '.join(e.cmd)}")
