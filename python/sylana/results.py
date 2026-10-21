"""Result values returned by the public API."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class SymbolicValue:
    """A value that may be concrete or an unresolved symbolic expression."""

    name: str
    width_bytes: int
    concrete: Optional[bytes] = None
    expression: Optional[str] = None

    @property
    def is_concrete(self) -> bool:
        return self.concrete is not None

    def as_int(self) -> Optional[int]:
        if self.concrete is None:
            return None
        return int.from_bytes(self.concrete, "little")

    def hex(self) -> str:
        if self.concrete is None:
            return f"<symbolic:{self.name}>"
        return f"0x{self.as_int():0{2 * len(self.concrete)}x}"

    def __repr__(self) -> str:
        return self.hex()


@dataclass(frozen=True)
class AccountState:
    """A single account's mutable state."""

    key: bytes
    lamports: int
    owner: bytes
    data: bytes
    executable: bool = False


@dataclass(frozen=True)
class SimulationPath:
    """One feasible execution path found for a symbolic message."""

    return_value: int
    succeeded: bool
    accounts_after: tuple[AccountState, ...]
    witness: dict[str, SymbolicValue] = field(default_factory=dict)
    # Path-condition clauses over the symbolic inputs (raw KQuery text), i.e. the
    # branch decisions that define this path, e.g. "amount <= 100".
    constraints: tuple[str, ...] = ()
    log: str = ""  # tail of the program's own log output on this path


@dataclass(frozen=True)
class SimulationResult:
    """Every feasible path for a simulate_full_tx call."""

    paths: tuple[SimulationPath, ...]
    # KLEE witnesses of paths that did not complete (test000N.<kind>.err):
    # solver timeouts, unmodeled CPIs, program aborts.
    dropped: tuple[str, ...] = ()

    @property
    def is_concrete(self) -> bool:
        return len(self.paths) == 1

    def single(self) -> SimulationPath:
        if len(self.paths) != 1:
            raise ValueError(f"expected one path, found {len(self.paths)}")
        return self.paths[0]


@dataclass(frozen=True)
class CallArgs:
    """The argument registers observed at one call to the target function."""

    pc: int
    call_index: int
    args: tuple[SymbolicValue, ...]
