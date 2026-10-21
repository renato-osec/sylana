"""Toolchain-independent message and account model, plus solders adapters.

The public API accepts solders/solana-py objects, but everything downstream
works on these plain dataclasses so the engine and tests never import solders.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Sequence

PUBKEY_LEN = 32


def _to_bytes32(value: Any, what: str) -> bytes:
    """Coerce a solders Pubkey/Hash, bytes, or int list into 32 bytes."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    elif isinstance(value, (list, tuple)):
        raw = bytes(value)
    else:
        # solders Pubkey/Hash implement __bytes__.
        raw = bytes(value)
    if len(raw) != PUBKEY_LEN:
        raise ValueError(f"{what} must be {PUBKEY_LEN} bytes, got {len(raw)}")
    return raw


@dataclass(frozen=True)
class Instruction:
    """A compiled instruction referencing accounts by index."""

    program_id_index: int
    account_indices: tuple[int, ...]
    data: bytes


@dataclass(frozen=True)
class MessageModel:
    """A normalized Solana message independent of any SDK type."""

    version: str
    account_keys: tuple[bytes, ...]
    num_required_signatures: int
    num_readonly_signed: int
    num_readonly_unsigned: int
    recent_blockhash: bytes
    instructions: tuple[Instruction, ...]

    def program_id(self, instruction_index: int) -> bytes:
        ix = self.instructions[instruction_index]
        return self.account_keys[ix.program_id_index]


@dataclass(frozen=True)
class AccountInput:
    """Pre-execution state of one account referenced by the message."""

    key: bytes
    lamports: int = 0
    owner: bytes = b"\x00" * PUBKEY_LEN
    data: bytes = b""
    is_signer: bool = False
    is_writable: bool = False
    executable: bool = False


def _call_or_get(obj: object, name: str) -> Optional[object]:
    attr = getattr(obj, name, None)
    if attr is None:
        return None
    return attr() if callable(attr) else attr


def _looks_like_message(obj: object) -> bool:
    return hasattr(obj, "account_keys") and hasattr(obj, "instructions")


def extract_message(source: Any) -> Any:
    """Return the underlying message from a tx wrapper or the message itself.

    Accepts anything exposing message()/message (solders Transaction,
    VersionedTransaction, a user wrapper) or a message-like object directly.
    """
    if isinstance(source, MessageModel) or _looks_like_message(source):
        return source
    message = _call_or_get(source, "message")
    if message is None:
        raise TypeError("object has no message() method or message attribute")
    return message


def to_model(source: Any) -> MessageModel:
    """Normalize a solders message (or MessageModel) into a MessageModel."""
    message = extract_message(source)
    if isinstance(message, MessageModel):
        return message

    account_keys = tuple(
        _to_bytes32(key, "account key") for key in message.account_keys
    )
    header = getattr(message, "header", None)
    if header is not None:
        num_sig = int(header.num_required_signatures)
        ro_signed = int(header.num_readonly_signed_accounts)
        ro_unsigned = int(header.num_readonly_unsigned_accounts)
    else:
        num_sig, ro_signed, ro_unsigned = 1, 0, 0

    blockhash = getattr(message, "recent_blockhash", None)
    recent = _to_bytes32(blockhash, "recent blockhash") if blockhash is not None \
        else b"\x00" * PUBKEY_LEN

    instructions = []
    for ix in message.instructions:
        accounts = getattr(ix, "accounts", ())
        instructions.append(
            Instruction(
                program_id_index=int(ix.program_id_index),
                account_indices=tuple(int(a) for a in bytes(accounts))
                if isinstance(accounts, (bytes, bytearray))
                else tuple(int(a) for a in accounts),
                data=bytes(ix.data),
            )
        )

    version = "legacy" if header is not None and not hasattr(
        message, "address_table_lookups"
    ) else getattr(message, "version", "v0")
    if not isinstance(version, str):
        version = "v0"
    return MessageModel(
        version=version,
        account_keys=account_keys,
        num_required_signatures=num_sig,
        num_readonly_signed=ro_signed,
        num_readonly_unsigned=ro_unsigned,
        recent_blockhash=recent,
        instructions=tuple(instructions),
    )


def accounts_from(
    entries: Optional[Iterable[object] | Mapping[object, object]],
) -> dict[bytes, AccountInput]:
    """Normalize a user-supplied accounts snapshot keyed by pubkey."""
    if entries is None:
        return {}
    result: dict[bytes, AccountInput] = {}
    items: Sequence[tuple[object, object]]
    if isinstance(entries, Mapping):
        items = list(entries.items())
    else:
        items = [(getattr(e, "key", None) or getattr(e, "pubkey"), e) for e in entries]
    for key, value in items:
        account = _coerce_account(key, value)
        result[account.key] = account
    return result


def _coerce_account(key: Any, value: Any) -> AccountInput:
    if isinstance(value, AccountInput):
        return value
    key_bytes = _to_bytes32(key, "account key")
    # solders Account exposes lamports/owner/data/executable.
    lamports = int(getattr(value, "lamports", 0) or 0)
    owner_raw = getattr(value, "owner", None)
    owner = _to_bytes32(owner_raw, "owner") if owner_raw is not None else b"\x00" * PUBKEY_LEN
    data = bytes(getattr(value, "data", b"") or b"")
    executable = bool(getattr(value, "executable", False))
    return AccountInput(
        key=key_bytes,
        lamports=lamports,
        owner=owner,
        data=data,
        executable=executable,
    )
