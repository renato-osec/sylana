"""sylana: symbolic execution of Solana sBPF programs, with a solders-friendly API.

Public entry points:
- to_symbolic(message, symbolic=..., accounts=...) -> SymbolicMessage
- SymbolicElf.load(path).simulate_full_tx(symbolic_message) -> SimulationResult
- SymbolicElf.load(path).get_function_call_args(symbolic_message, function) -> [CallArgs]

CPIs to contracts sylana does not model raise SylanaUnsupportedCpi.
"""

from __future__ import annotations

from .elf import SymbolicElf
from .errors import (
    SylanaEngineError,
    SylanaError,
    SylanaToolchainMissing,
    SylanaUnsupported,
    SylanaUnsupportedCpi,
)
from .results import (
    AccountState,
    CallArgs,
    SimulationPath,
    SimulationResult,
    SymbolicValue,
)
from .session import SimulationSession
from .symbolic import (
    Constraint,
    FieldKind,
    SymbolicField,
    SymbolicMessage,
    sym,
    to_symbolic,
)
from .toolchain import Toolchain

__all__ = [
    "to_symbolic",
    "sym",
    "SymbolicMessage",
    "SymbolicField",
    "Constraint",
    "FieldKind",
    "SymbolicElf",
    "Toolchain",
    "SimulationResult",
    "SimulationPath",
    "SimulationSession",
    "AccountState",
    "CallArgs",
    "SymbolicValue",
    "SylanaError",
    "SylanaUnsupported",
    "SylanaUnsupportedCpi",
    "SylanaToolchainMissing",
    "SylanaEngineError",
]

__version__ = "0.1.0"
