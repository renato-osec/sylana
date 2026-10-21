"""Locate and run the native engine binaries.

The normalizer and emitter are project build artifacts; clang, llvm-link, opt
and klee come from the pinned nix shell (runtime/shell.nix). When those are not
already on PATH, commands are wrapped in `nix-shell shell.nix --run`.
"""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

from .errors import SylanaEngineError, SylanaToolchainMissing


def project_root() -> Path:
    """The sylana project root, two levels up from this file."""
    return Path(__file__).resolve().parents[2]


@dataclass
class Toolchain:
    root: Path
    normalize: Optional[Path]
    emitter: Optional[Path]
    runtime_dir: Path
    shell_nix: Optional[Path]
    klee_on_path: bool
    records_calls: bool
    klee_session: Optional[Path]
    klee_runtime_lib: Optional[Path]
    klee_runtime_suffix: str

    @classmethod
    def discover(cls, root: Optional[Path] = None) -> "Toolchain":
        root = root or project_root()
        normalize = _first_existing(
            os.environ.get("SYLANA_NORMALIZE"),
            root / "normalize" / "target" / "release" / "sbpf-normalize",
            root / "normalize" / "target" / "debug" / "sbpf-normalize",
        )
        emitter = _first_existing(
            os.environ.get("SYLANA_EMITTER"),
            *(Path(p) for p in glob.glob(str(root / "emitter" / "build*" / "sbpf-llvm-emit"))),
        )
        klee_session = _first_existing(
            os.environ.get("SYLANA_KLEE_SESSION"),
            root / "klee-session" / "result-klee-session" / "bin" / "klee-session",
            shutil.which("klee-session"),
        )
        klee_runtime_lib = None
        klee_runtime_suffix = "64_Release"
        if klee_session is not None:
            candidate = klee_session.resolve().parents[1] / "lib" / "klee" / "runtime"
            if candidate.exists():
                klee_runtime_lib = candidate
                klee_runtime_suffix = _detect_runtime_suffix(candidate)
        shell_nix = root / "runtime" / "shell.nix"
        return cls(
            root=root,
            normalize=normalize,
            emitter=emitter,
            runtime_dir=root / "runtime",
            shell_nix=shell_nix if shell_nix.exists() else None,
            klee_on_path=shutil.which("klee") is not None,
            records_calls=_normalize_records_calls(normalize),
            klee_session=klee_session,
            klee_runtime_lib=klee_runtime_lib,
            klee_runtime_suffix=klee_runtime_suffix,
        )

    def require(self, *, need_klee: bool) -> None:
        """Raise if a needed binary is absent, naming how to obtain it."""
        missing = []
        if self.normalize is None:
            missing.append("normalizer (build: cargo build --release in normalize/)")
        if self.emitter is None:
            missing.append("emitter (build: cmake --build emitter/build in the nix shell)")
        if need_klee and not self.klee_on_path and self.shell_nix is None:
            missing.append("klee (enter runtime/shell.nix or install KLEE 3.1)")
        if missing:
            raise SylanaToolchainMissing("; ".join(missing))

    def klee_command(self, script: str) -> list[str]:
        """Wrap a bash script so klee/clang/llvm run under the pinned shell."""
        if self.klee_on_path or self.shell_nix is None:
            return ["bash", "-c", script]
        return [
            "nix-shell", str(self.shell_nix), "--run", script,
        ]


def _first_existing(*candidates: object) -> Optional[Path]:
    for candidate in candidates:
        if candidate is None:
            continue
        path = Path(str(candidate))
        if path.exists():
            return path
    return None


def _detect_runtime_suffix(runtime_lib: Path) -> str:
    """Pick the OptSuffix from installed libkleeRuntimeIntrinsic<suffix>.bca."""
    names = sorted(p.name for p in runtime_lib.glob("libkleeRuntimeIntrinsic*.bca"))
    suffixes = [n[len("libkleeRuntimeIntrinsic"):-len(".bca")] for n in names]
    for preferred in ("64_Release", "64_Release+Debug", "64_Release+Asserts"):
        if preferred in suffixes:
            return preferred
    return suffixes[0] if suffixes else "64_Release"


def _normalize_records_calls(normalize: Optional[Path]) -> bool:
    if normalize is None:
        return False
    try:
        result = subprocess.run(
            [str(normalize)], capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError):
        return False
    usage = (result.stdout or "") + (result.stderr or "")
    return "--record-calls-to" in usage


def run(cmd: Sequence[str], *, cwd: Optional[Path] = None, env: Optional[dict] = None) -> str:
    """Run a command, returning stdout and raising on failure."""
    result = subprocess.run(
        list(cmd), cwd=str(cwd) if cwd else None, env=env,
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise SylanaEngineError(
            f"command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr}"
        )
    return result.stdout
