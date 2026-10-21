"""SymbolicElf: the loaded, liftable program and its analyses."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional, Union

from . import harness, pipeline
from .errors import (
    SylanaEngineError,
    SylanaError,
    SylanaUnsupported,
    SylanaUnsupportedCpi,
)
from .ktest import KTest, constraints_from_kquery, parse_file
from .model import PUBKEY_LEN
from .results import (
    AccountState,
    CallArgs,
    SimulationPath,
    SimulationResult,
    SymbolicValue,
)
from .session import SimulationSession
from .symbolic import SymbolicMessage
from .toolchain import Toolchain


class SymbolicElf:
    """A compiled Solana sBPF program prepared for symbolic execution."""

    def __init__(
        self,
        elf_path: Path,
        toolchain: Toolchain,
        workdir: Path,
        program_id: Optional[bytes],
    ) -> None:
        self._elf = elf_path
        self._tc = toolchain
        self._workdir = workdir
        self._program_id = program_id
        self._functions: Optional[dict[str, int]] = None
        # The program lift (normalize->emit->llvm-as) depends only on the ELF,
        # not the message, and is the dominant fixed cost (~14s emit). Cache it
        # so running several symbolic queries on one loaded program pays it once.
        self._lift_cache: dict = {}

    @classmethod
    def load(
        cls,
        path: Union[str, Path],
        *,
        program_id: Optional[bytes] = None,
        toolchain: Optional[Toolchain] = None,
        workdir: Optional[Union[str, Path]] = None,
    ) -> "SymbolicElf":
        """Load a compiled .so program. program_id is its deployed address."""
        elf_path = Path(path).resolve()
        if not elf_path.exists():
            raise SylanaError(f"program not found: {elf_path}")
        tc = toolchain or Toolchain.discover()
        work = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="sylana-"))
        return cls(elf_path, tc, work, program_id)

    @property
    def functions(self) -> dict[str, int]:
        """Map of local function name to normalized entry PC."""
        if self._functions is None:
            self._functions = self._load_function_map()
        return self._functions

    def _load_function_map(self) -> dict[str, int]:
        self._tc.require(need_klee=False)
        assert self._tc.normalize is not None
        out = self._workdir / "map"
        out.mkdir(parents=True, exist_ok=True)
        from .toolchain import run
        text = run([
            str(self._tc.normalize), str(self._elf), str(out / "program.bin"),
            "--summarize-log-formats",
        ])
        functions, _, _ = pipeline.parse_map(text)
        return functions

    def _lift(self, out_dir: Path, record_pc: Optional[int] = None):
        key = (str(out_dir), record_pc)
        cached = self._lift_cache.get(key)
        if cached is None:
            cached = pipeline.lift(self._tc, self._elf, out_dir, record_pc=record_pc)
            self._lift_cache[key] = cached
        return cached

    def _resolve_program_id(self, message: SymbolicMessage) -> bytes:
        if self._program_id is not None:
            return self._program_id
        if len(message.model.instructions) == 1:
            return message.model.program_id(0)
        raise SylanaError(
            "program_id is required for a multi-instruction message; "
            "pass it to SymbolicElf.load"
        )

    def simulate_full_tx(
        self, message: SymbolicMessage, *, data_bytes: Optional[int] = 256
    ) -> SimulationResult:
        """Run the whole entrypoint for a symbolic message.

        Returns one path per feasible symbolic-input class, each with the
        entrypoint return value and every account's post-execution state.
        `data_bytes` caps exported account data per account; None exports all.
        """
        program_id = self._resolve_program_id(message)
        source = harness.generate(message, program_id, data_bytes=data_bytes)
        artifacts = self._lift(self._workdir / "simulate")
        result = pipeline.run_klee(self._tc, artifacts, source, "simulate")
        layout = harness.build_layout(message, program_id)
        # Paths that hit a solver timeout, an unmodeled CPI or an abort are
        # reported as dropped; only an empty result is an error.
        paths = [self._path_from_ktest(parse_file(str(p)), message, layout, p)
                 for p in result.completed_ktests()]
        if not paths:
            self._raise_on_model_error(result)
            # KLEE drops a state whose solver query fails; say so instead of
            # claiming infeasibility.
            solver = [l for l in result.stderr.splitlines()
                      if "STP" in l or "solver" in l.lower() or "Symbolic memory access" in l]
            raise SylanaError(
                "simulation produced no feasible path"
                + (": " + " | ".join(solver[-2:]) if solver else "")
            )
        return SimulationResult(paths=tuple(paths), dropped=tuple(sorted(set(result.errors))))

    def get_function_call_args(
        self, message: SymbolicMessage, function: Union[str, int]
    ) -> list[CallArgs]:
        """Return the argument registers at every call to a function.

        `function` is a local function name (see .functions) or a normalized PC.
        """
        pc = function if isinstance(function, int) else self.functions.get(function)
        if pc is None:
            raise SylanaError(f"unknown function: {function}")
        if not self._tc.records_calls:
            raise SylanaUnsupported(
                "call-argument capture needs a normalizer built with "
                "--record-calls-to; rebuild normalize/"
            )
        program_id = self._resolve_program_id(message)
        source = harness.generate(message, program_id, record_calls=True)
        artifacts = self._lift(self._workdir / "callargs", record_pc=pc)
        result = pipeline.run_klee(self._tc, artifacts, source, "callargs")
        self._raise_on_model_error(result)
        calls: list[CallArgs] = []
        for ktest_path in result.ktests:
            calls.extend(self._calls_from_ktest(parse_file(str(ktest_path)), pc))
        return calls

    def simulate_session(
        self, message: SymbolicMessage, *, data_bytes=None
    ) -> SimulationSession:
        """Open a live session: run the program, keep its memory queryable.

        Returns a SimulationSession whose read()/deref() concretize any address
        in a terminated state's symbolic memory. The state lives until the
        session is closed (context exit or garbage collection).
        """
        if self._tc.klee_session is None:
            raise SylanaUnsupported(
                "klee-session is not built; build klee-session/fork.nix"
            )
        program_id = self._resolve_program_id(message)
        source = harness.generate(message, program_id, data_bytes=data_bytes)
        artifacts = self._lift(self._workdir / "session")
        linked = pipeline.build_linked(self._tc, artifacts, source, "session")
        return SimulationSession.spawn(
            self._tc.klee_session, linked, self._tc.klee_runtime_lib,
            self._tc.klee_runtime_suffix,
        )

    def _raise_on_model_error(self, result: pipeline.KleeRun) -> None:
        # Any KLEE .err means a path terminated abnormally; never return a
        # witness for it. Unknown CPIs are the one expected boundary.
        if not result.errors:
            return
        if any(e.endswith(("cpi.err", "cpi-runtime.err")) for e in result.errors):
            raise SylanaUnsupportedCpi(
                "program invoked a CPI to a contract sylana does not model"
            )
        raise SylanaEngineError(
            f"execution terminated with error(s): {sorted(set(result.errors))}"
        )

    def _path_from_ktest(
        self, ktest: KTest, message: SymbolicMessage, layout: harness.Layout,
        ktest_path: Optional[Path] = None,
    ) -> SimulationPath:
        objects = ktest.as_dict()
        return_bytes = objects.get("return_value", b"\x00" * 8)
        return_value = int.from_bytes(return_bytes, "little")
        witness = {
            field.name: SymbolicValue(
                name=field.name,
                width_bytes=len(objects.get(field.name, b"")),
                concrete=objects.get(field.name),
            )
            for field in message.symbolic
            if field.name in objects
        }
        accounts_after = []
        for account in layout.accounts:
            lamports = int.from_bytes(
                objects.get(f"account{account.index}.lamports_after", b"\x00" * 8),
                "little",
            )
            data = objects.get(f"account{account.index}.data_after", b"")
            state = message.account_for_index(account.index)
            owner = state.owner if state else b"\x00" * PUBKEY_LEN
            accounts_after.append(
                AccountState(
                    key=account.key,
                    lamports=lamports,
                    owner=owner,
                    data=data,
                )
            )
        constraints: tuple[str, ...] = ()
        if ktest_path is not None:
            kquery = Path(str(ktest_path)).with_suffix(".kquery")
            if kquery.exists():
                constraints = constraints_from_kquery(kquery.read_text())
        return SimulationPath(
            return_value=return_value,
            succeeded=return_value == 0,
            accounts_after=tuple(accounts_after),
            witness=witness,
            log=objects.get("log", b"").split(b"\x00", 1)[0].decode("utf-8", "replace"),
            constraints=constraints,
        )

    def _calls_from_ktest(self, ktest: KTest, pc: int) -> list[CallArgs]:
        objects = ktest.as_dict()
        indices = sorted({
            int(name.split(".")[1])
            for name in objects
            if name.startswith("callarg.") and name.count(".") == 2
        })
        calls = []
        for call_index in indices:
            args = []
            for reg in range(1, 6):
                key = f"callarg.{call_index}.r{reg}"
                if key not in objects:
                    continue
                args.append(SymbolicValue(
                    name=key, width_bytes=len(objects[key]), concrete=objects[key]
                ))
            calls.append(CallArgs(pc=pc, call_index=call_index, args=tuple(args)))
        return calls
