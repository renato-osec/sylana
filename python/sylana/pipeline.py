"""Drive normalize -> emit -> compile -> link -> klee for one program."""

from __future__ import annotations

import glob
import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .errors import SylanaEngineError
from .toolchain import Toolchain, run

# A symbolic index into a large object (the program's read-only image, the
# heap) turns into an array query the solver cannot finish; concretize those
# indexes and bound every query so a hard one ends the state instead of hanging.
# --solver-optimize-divides turns the many bps/scale constant divisions into
# shift/multiply, which the bitvector solver handles far faster; override the
# whole set (e.g. to select --solver-backend=z3) with $SYLANA_KLEE_FLAGS.
KLEE_SOLVER_FLAGS = os.environ.get(
    "SYLANA_KLEE_FLAGS",
    "--max-sym-array-size=4096 --max-solver-time=30s --solver-optimize-divides",
)

# KLEE witness suffixes that mean an internal model boundary, not a program bug.
_MODEL_ERROR_SUFFIXES = (
    "cpi.err", "cpi-runtime.err", "callx.err", "syscall.err",
    "model.err", "oracle.err", "layout.err", "abort.err", "arithmetic.err",
)


@dataclass
class LiftArtifacts:
    out_dir: Path
    program_bc: Path
    functions: dict[str, int]
    sbpf_version: int
    entry_pc: int


@dataclass
class KleeRun:
    out_dir: Path
    ktests: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stderr: str = ""

    def has_error(self, suffix: str) -> bool:
        return any(e.endswith(suffix) for e in self.errors)

    def completed_ktests(self) -> list[Path]:
        """Tests whose path ran to completion (no KLEE .err for that test)."""
        errored = {e.split(".", 1)[0] for e in self.errors}
        return [p for p in self.ktests if p.name.split(".", 1)[0] not in errored]


def parse_map(text: str) -> tuple[dict[str, int], int, int]:
    """Parse the normalizer summary into (functions, sbpf_version, entry_pc)."""
    functions: dict[str, int] = {}
    sbpf_version = 0
    entry_pc = 0
    for line in text.splitlines():
        if line.startswith("function."):
            head, _, tail = line.partition("=")
            pc = int(head.split(".", 1)[1])
            name = tail.split(",", 1)[1] if "," in tail else tail
            functions[name] = pc
        elif line.startswith("sbpf_version=") and line[13:].isdigit():
            sbpf_version = int(line[13:])
        elif line.startswith("normalized_entry_pc="):
            entry_pc = int(line.split("=", 1)[1])
    return functions, sbpf_version, entry_pc


def rodata_source(map_text: str, blob: bytes) -> str:
    """C source placing the program's read-only image at its guest address.

    The normalizer splits the image into regions (e.g. around the Rust digit
    table) so the runtime maps each as its own KLEE object.
    """
    vm_addr = 0
    ends: list[int] = []
    for line in map_text.splitlines():
        if line.startswith("rodata_vm_addr="):
            vm_addr = int(line.split("=", 1)[1], 0)
        elif line.startswith("rodata_region.end="):
            ends.append(int(line.split("=", 1)[1]))
    if not ends:
        ends = [len(blob)]
    # Scalar symbols override the runtime's weak defaults with matching types.
    return (
        "#include <stdint.h>\n"
        f"static const uint8_t bytes[] = {{{','.join(map(str, blob))}}};\n"
        f"static const uint64_t ends[] = {{{','.join(map(str, ends))}}};\n"
        "const uint8_t *const sbpf_program_rodata = bytes;\n"
        f"const uint64_t sbpf_program_rodata_vm_addr = {vm_addr}ULL;\n"
        "const uint64_t *const sbpf_program_rodata_region_ends = ends;\n"
        f"const uint64_t sbpf_program_rodata_region_count = {len(ends)};\n"
    )


def lift(
    tc: Toolchain,
    elf_path: Path,
    out_dir: Path,
    *,
    record_pc: Optional[int] = None,
) -> LiftArtifacts:
    """Normalize the whole program and emit linkable LLVM bitcode."""
    tc.require(need_klee=True)
    assert tc.normalize is not None and tc.emitter is not None
    out_dir.mkdir(parents=True, exist_ok=True)
    program_bin = out_dir / "program.bin"

    normalize_cmd = [str(tc.normalize), str(elf_path), str(program_bin)]
    # Summarizing turns formatted msg!() strings into "" so symbolic arguments
    # cannot fork per formatted byte; keep them when debugging a program error.
    if not os.environ.get("SYLANA_KEEP_LOG_FORMATS"):
        normalize_cmd.append("--summarize-log-formats")
    if record_pc is not None:
        normalize_cmd += ["--record-calls-to", str(record_pc)]
    map_text = run(normalize_cmd)
    (out_dir / "program.map").write_text(map_text)
    functions, sbpf_version, entry_pc = parse_map(map_text)
    (out_dir / "rodata.c").write_text(
        rodata_source(map_text, (out_dir / "program.bin.rodata").read_bytes())
    )

    script = f"""
set -euo pipefail
if [ -n "${{TMPDIR:-}}" ] && [ ! -d "${{TMPDIR}}" ]; then unset TMPDIR; fi
{shlex.quote(str(tc.emitter))} {shlex.quote(str(program_bin))} \
  {shlex.quote(str(program_bin) + '.callx-targets')} > {shlex.quote(str(out_dir / 'program.ll'))}
llvm-as {shlex.quote(str(out_dir / 'program.ll'))} -o {shlex.quote(str(out_dir / 'program.bc'))}
opt -passes=verify {shlex.quote(str(out_dir / 'program.bc'))} -disable-output
"""
    run(tc.klee_command(script))
    return LiftArtifacts(
        out_dir=out_dir,
        program_bc=out_dir / "program.bc",
        functions=functions,
        sbpf_version=sbpf_version,
        entry_pc=entry_pc,
    )


def build_linked(
    tc: Toolchain,
    artifacts: LiftArtifacts,
    harness_source: str,
    name: str,
) -> Path:
    """Compile a harness and link it with the lift and runtime into one .bc."""
    out_dir = artifacts.out_dir
    harness_c = out_dir / f"{name}.c"
    harness_c.write_text(harness_source)
    runtime = tc.runtime_dir
    linked = out_dir / f"{name}.linked.bc"
    clang_flags = "-emit-llvm -c -g -O0 -U_FORTIFY_SOURCE -Xclang -disable-O0-optnone"
    # The syscall layer plus the CPI abstract-program models under programs/.
    runtime_sources = [
        "sbpf_runtime.c",
        "sbpf_sha256.c",
        "programs/cpi.c",
        "programs/system_program.c",
        "programs/token_program.c",
    ]
    sources = [(runtime / src, out_dir / f"{Path(src).stem}.bc")
               for src in runtime_sources]
    sources.append((out_dir / "rodata.c", out_dir / "rodata.bc"))
    sources.append((harness_c, out_dir / f"{name}.bc"))
    compiles = "\n".join(
        f'clang -I"$klee_inc" -I{shlex.quote(str(runtime))} {clang_flags} '
        f'{shlex.quote(str(src))} -o {shlex.quote(str(obj))}'
        for src, obj in sources
    )
    link_inputs = " ".join(
        shlex.quote(str(p))
        for p in [artifacts.program_bc, *(obj for _, obj in sources)]
    )
    script = f"""
set -euo pipefail
if [ -n "${{TMPDIR:-}}" ] && [ ! -d "${{TMPDIR}}" ]; then unset TMPDIR; fi
klee_inc="$(dirname "$(dirname "$(command -v klee)")")/include"
export NIX_HARDENING_ENABLE=
{compiles}
llvm-link {link_inputs} -o {shlex.quote(str(linked))}
opt -passes=verify {shlex.quote(str(linked))} -disable-output
"""
    run(tc.klee_command(script))
    return linked


def run_klee(
    tc: Toolchain,
    artifacts: LiftArtifacts,
    harness_source: str,
    name: str,
) -> KleeRun:
    """Build the linked module and run KLEE one-shot over it."""
    out_dir = artifacts.out_dir
    linked = build_linked(tc, artifacts, harness_source, name)
    klee_out = out_dir / f"klee-{name}"
    script = f"""
set -euo pipefail
if [ -n "${{TMPDIR:-}}" ] && [ ! -d "${{TMPDIR}}" ]; then unset TMPDIR; fi
rm -rf {shlex.quote(str(klee_out))}
ulimit -s unlimited 2>/dev/null || true
klee --output-dir={shlex.quote(str(klee_out))} --optimize=false \
  --write-kqueries {KLEE_SOLVER_FLAGS} {shlex.quote(str(linked))} 2>{shlex.quote(str(out_dir / (name + '.klee.log')))} || true
"""
    run(tc.klee_command(script))

    stderr = ""
    log = out_dir / f"{name}.klee.log"
    if log.exists():
        stderr = log.read_text(errors="replace")
    ktests = sorted(Path(p) for p in glob.glob(str(klee_out / "*.ktest")))
    errors = [os.path.basename(p) for p in glob.glob(str(klee_out / "*.err"))]
    if not klee_out.exists():
        raise SylanaEngineError(f"klee produced no output for {name}")
    return KleeRun(out_dir=klee_out, ktests=ktests, errors=errors, stderr=stderr)


def model_error(run_result: KleeRun) -> Optional[str]:
    """Return the first model-boundary error suffix present, if any."""
    for suffix in _MODEL_ERROR_SUFFIXES:
        if run_result.has_error(suffix):
            return suffix
    return None
