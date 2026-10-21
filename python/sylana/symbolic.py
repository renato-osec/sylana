"""Symbolic-field selectors, the SymbolicMessage, and to_symbolic()."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping, Optional

from .model import AccountInput, MessageModel, accounts_from, to_model


class FieldKind(Enum):
    INSTRUCTION_DATA = "instruction_data"
    ACCOUNT_KEY = "account_key"
    ACCOUNT_OWNER = "account_owner"
    ACCOUNT_LAMPORTS = "account_lamports"
    ACCOUNT_DATA = "account_data"
    RECENT_BLOCKHASH = "recent_blockhash"


@dataclass(frozen=True)
class Constraint:
    """A klee_assume applied to a symbolic field: field OP value."""

    field: "SymbolicField"
    op: str
    value: object


@dataclass(frozen=True)
class SymbolicField:
    """One message or account region to expose to the solver."""

    kind: FieldKind
    index: int = 0
    byte_range: Optional[tuple[int, int]] = None

    def eq(self, value: object) -> Constraint:
        return Constraint(self, "==", value)

    def ne(self, value: object) -> Constraint:
        return Constraint(self, "!=", value)

    def lt(self, value: int) -> Constraint:
        return Constraint(self, "<", value)

    def le(self, value: int) -> Constraint:
        return Constraint(self, "<=", value)

    def gt(self, value: int) -> Constraint:
        return Constraint(self, ">", value)

    def ge(self, value: int) -> Constraint:
        return Constraint(self, ">=", value)

    @property
    def name(self) -> str:
        base = {
            FieldKind.INSTRUCTION_DATA: f"ix{self.index}.data",
            FieldKind.ACCOUNT_KEY: f"account{self.index}.key",
            FieldKind.ACCOUNT_OWNER: f"account{self.index}.owner",
            FieldKind.ACCOUNT_LAMPORTS: f"account{self.index}.lamports",
            FieldKind.ACCOUNT_DATA: f"account{self.index}.data",
            FieldKind.RECENT_BLOCKHASH: "recent_blockhash",
        }[self.kind]
        if self.byte_range is not None:
            base += f"[{self.byte_range[0]}:{self.byte_range[1]}]"
        return base


class sym:
    """Factory namespace for symbolic-field selectors."""

    @staticmethod
    def instruction_data(index: int = 0, byte_range: Optional[tuple[int, int]] = None) -> SymbolicField:
        return SymbolicField(FieldKind.INSTRUCTION_DATA, index, byte_range)

    @staticmethod
    def account_key(index: int) -> SymbolicField:
        return SymbolicField(FieldKind.ACCOUNT_KEY, index)

    @staticmethod
    def account_owner(index: int) -> SymbolicField:
        return SymbolicField(FieldKind.ACCOUNT_OWNER, index)

    @staticmethod
    def account_lamports(index: int) -> SymbolicField:
        return SymbolicField(FieldKind.ACCOUNT_LAMPORTS, index)

    @staticmethod
    def account_data(index: int, byte_range: Optional[tuple[int, int]] = None) -> SymbolicField:
        return SymbolicField(FieldKind.ACCOUNT_DATA, index, byte_range)

    @staticmethod
    def recent_blockhash() -> SymbolicField:
        return SymbolicField(FieldKind.RECENT_BLOCKHASH)


@dataclass(frozen=True)
class SymbolicMessage:
    """A message plus the fields chosen to be symbolic and the account state."""

    model: MessageModel
    symbolic: tuple[SymbolicField, ...]
    accounts: dict[bytes, AccountInput]
    assumptions: tuple[Constraint, ...] = ()
    # Raw sysvar account data ("rent", "clock") as of the simulated slot.
    sysvars: dict[str, bytes] = field(default_factory=dict)

    @property
    def is_concrete(self) -> bool:
        return len(self.symbolic) == 0

    def constraints_for(self, field: SymbolicField) -> list[Constraint]:
        return [c for c in self.assumptions if c.field == field]

    def field_names(self) -> tuple[str, ...]:
        return tuple(f.name for f in self.symbolic)

    def account_for_index(self, index: int) -> Optional[AccountInput]:
        key = self.model.account_keys[index]
        return self.accounts.get(key)


def _validate(model: MessageModel, fields: Iterable[SymbolicField]) -> None:
    account_count = len(model.account_keys)
    ix_count = len(model.instructions)
    for f in fields:
        if f.kind is FieldKind.INSTRUCTION_DATA and not (0 <= f.index < ix_count):
            raise IndexError(f"instruction {f.index} out of range ({ix_count})")
        if f.kind in (
            FieldKind.ACCOUNT_KEY,
            FieldKind.ACCOUNT_OWNER,
            FieldKind.ACCOUNT_LAMPORTS,
            FieldKind.ACCOUNT_DATA,
        ) and not (0 <= f.index < account_count):
            raise IndexError(f"account {f.index} out of range ({account_count})")


def to_symbolic(
    source: Any,
    *,
    symbolic: Iterable[SymbolicField] = (),
    accounts: Any = None,
    assume: Iterable[Constraint] = (),
    sysvars: Optional[Mapping[str, Any]] = None,
) -> SymbolicMessage:
    """Turn a message (or tx exposing message()) into a SymbolicMessage.

    `symbolic` selects which fields the solver may vary; the default keeps the
    message fully concrete. `accounts` supplies the pre-execution account state
    (solders Account values or AccountInput) needed to simulate. `assume` adds
    klee_assume constraints (e.g. sym.account_lamports(2).le(100)); a
    constrained field is made symbolic automatically. `sysvars` maps "rent"
    and/or "clock" to that sysvar's account (or raw data) so the runtime uses
    the chain's values instead of its canonical defaults.
    """
    model = to_model(source)
    assumptions = tuple(assume)
    # A constrained field is symbolic even if not listed explicitly.
    fields = list(symbolic)
    for constraint in assumptions:
        if constraint.field not in fields:
            fields.append(constraint.field)
    _validate(model, fields)
    return SymbolicMessage(
        model=model,
        symbolic=tuple(fields),
        accounts=accounts_from(accounts),
        assumptions=assumptions,
        sysvars={name: bytes(getattr(value, "data", value))
                 for name, value in (sysvars or {}).items()},
    )
