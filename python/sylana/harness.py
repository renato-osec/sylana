"""Generate a KLEE C harness and its input layout from a SymbolicMessage.

The layout mirrors runtime/templates/entrypoint.c and the Solana loader's
serialized input region. Post-execution state is exported with KLEE's
make_symbolic + assume idiom so one .ktest per path carries both the chosen
inputs and the resulting return value and account bytes.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from .errors import SylanaError
from .model import AccountInput, MessageModel
from .symbolic import FieldKind, SymbolicField, SymbolicMessage

NON_DUP_MARKER = 0xFF
MAX_PERMITTED_DATA_INCREASE = 10 * 1024
RENT_EPOCH = (1 << 64) - 1
ACCOUNT_HEADER = 8            # marker, signer, writable, exec, u32 pad
KEY_OFFSET = 8
OWNER_OFFSET = 40
LAMPORTS_OFFSET = 72
DATA_LEN_OFFSET = 80
DATA_OFFSET = 88
EXPORT_DATA_CAP = 256         # bytes of each account's data exported per path


@dataclass(frozen=True)
class AccountLayout:
    """Where one account landed in the serialized input buffer."""

    index: int
    key: bytes
    start: int
    data_length: int

    @property
    def lamports_offset(self) -> int:
        return self.start + LAMPORTS_OFFSET

    @property
    def data_offset(self) -> int:
        return self.start + DATA_OFFSET

    @property
    def owner_offset(self) -> int:
        return self.start + OWNER_OFFSET

    @property
    def key_offset(self) -> int:
        return self.start + KEY_OFFSET


@dataclass(frozen=True)
class Layout:
    """The full serialized input buffer plus offsets of interest."""

    template: bytes
    accounts: tuple[AccountLayout, ...]
    instruction_data_offset: int
    instruction_data_length: int


def _is_signer(model: MessageModel, index: int) -> bool:
    return index < model.num_required_signatures


def _is_writable(model: MessageModel, index: int) -> bool:
    total = len(model.account_keys)
    signed = model.num_required_signatures
    if index < signed:
        return index < signed - model.num_readonly_signed
    return index < total - model.num_readonly_unsigned


def _target_instruction(model: MessageModel, program_id: bytes) -> int:
    for i, _ in enumerate(model.instructions):
        if model.program_id(i) == program_id:
            return i
    raise SylanaError("message has no instruction for this program")


def _account_state(message: SymbolicMessage, index: int) -> AccountInput:
    existing = message.account_for_index(index)
    if existing is not None:
        return existing
    return AccountInput(key=message.model.account_keys[index])


def build_layout(message: SymbolicMessage, program_id: bytes) -> Layout:
    """Serialize the target instruction's accounts and data into one buffer."""
    model = message.model
    ix_index = _target_instruction(model, program_id)
    instruction = model.instructions[ix_index]

    buffer = bytearray()
    buffer += (len(instruction.account_indices)).to_bytes(8, "little")

    layouts: list[AccountLayout] = []
    for account_index in instruction.account_indices:
        state = _account_state(message, account_index)
        start = len(buffer)
        block = bytearray(ACCOUNT_HEADER)
        block[0] = NON_DUP_MARKER
        block[1] = 1 if (_is_signer(model, account_index) or state.is_signer) else 0
        block[2] = 1 if (_is_writable(model, account_index) or state.is_writable) else 0
        block[3] = 1 if state.executable else 0
        block += state.key
        block += state.owner
        block += int(state.lamports).to_bytes(8, "little")
        block += len(state.data).to_bytes(8, "little")
        block += state.data
        block += b"\x00" * MAX_PERMITTED_DATA_INCREASE
        buffer += block
        while len(buffer) % 8 != 0:
            buffer += b"\x00"
        buffer += RENT_EPOCH.to_bytes(8, "little")
        layouts.append(
            AccountLayout(
                index=account_index,
                key=state.key,
                start=start,
                data_length=len(state.data),
            )
        )

    buffer += len(instruction.data).to_bytes(8, "little")
    data_offset = len(buffer)
    buffer += instruction.data
    buffer += program_id

    return Layout(
        template=bytes(buffer),
        accounts=tuple(layouts),
        instruction_data_offset=data_offset,
        instruction_data_length=len(instruction.data),
    )


def _field_region(
    layout: Layout, model: MessageModel, program_id: bytes, field: SymbolicField
) -> tuple[int, int]:
    """Return (offset, size) in the input buffer for a symbolic field."""
    ix_index = _target_instruction(model, program_id)
    if field.kind is FieldKind.INSTRUCTION_DATA:
        if field.index != ix_index:
            raise SylanaError("symbolic instruction is not the simulated one")
        base = layout.instruction_data_offset
        if field.byte_range is None:
            return base, layout.instruction_data_length
        lo, hi = field.byte_range
        return base + lo, hi - lo
    account = _account_by_message_index(layout, field.index)
    if field.kind is FieldKind.ACCOUNT_KEY:
        return account.key_offset, 32
    if field.kind is FieldKind.ACCOUNT_OWNER:
        return account.owner_offset, 32
    if field.kind is FieldKind.ACCOUNT_LAMPORTS:
        return account.lamports_offset, 8
    if field.kind is FieldKind.ACCOUNT_DATA:
        if field.byte_range is None:
            return account.data_offset, account.data_length
        lo, hi = field.byte_range
        return account.data_offset + lo, hi - lo
    raise SylanaError(f"field {field.kind} is not part of the input buffer")


def _account_by_message_index(layout: Layout, message_index: int) -> AccountLayout:
    for account in layout.accounts:
        if account.index == message_index:
            return account
    raise SylanaError(f"account {message_index} is not used by this instruction")


def _c_bytes(data: bytes) -> str:
    return ",".join(str(b) for b in data)


def _constraint_lines(symvar: str, size: int, constraints, index: int) -> list[str]:
    """Emit klee_assume lines for a symbolic field's constraints."""
    lines: list[str] = []
    for j, c in enumerate(constraints):
        if isinstance(c.value, int):
            if size > 8:
                raise SylanaError("scalar constraint needs a field of <= 8 bytes")
            var = f"_c{index}_{j}"
            lines.append(
                f"{{ uint64_t {var} = 0; memcpy(&{var}, {symvar}, {size}); "
                f"klee_assume({var} {c.op} {c.value}ULL); }}"
            )
        elif isinstance(c.value, (bytes, bytearray)):
            if len(c.value) != size:
                raise SylanaError("byte constraint size does not match field")
            if c.op not in ("==", "!="):
                raise SylanaError("byte-field constraints support only eq/ne")
            terms = " && ".join(f"{symvar}[{k}] == {b}" for k, b in enumerate(c.value))
            expr = f"({terms})" if c.op == "==" else f"!({terms})"
            lines.append(f"klee_assume({expr});")
        else:
            raise SylanaError(f"unsupported constraint value: {c.value!r}")
    return lines


# bincode layouts of the Rent and Clock sysvar accounts
_RENT = struct.Struct("<QdB")
_CLOCK = struct.Struct("<QqQQq")


def _sysvar_lines(sysvars: dict[str, bytes]) -> list[str]:
    """Override the runtime's canonical sysvars with the chain's values."""
    lines: list[str] = []
    if "rent" in sysvars:
        if len(sysvars["rent"]) < _RENT.size:
            raise SylanaError("rent sysvar data is too short")
        per_byte_year, threshold, burn = _RENT.unpack_from(sysvars["rent"])
        lines.append(f"{{ struct sbpf_runtime_rent rent = {{{per_byte_year}ULL, {threshold!r}, {burn}}};"
                     " sbpf_runtime_set_rent(&rent); }")
    if "clock" in sysvars:
        if len(sysvars["clock"]) < _CLOCK.size:
            raise SylanaError("clock sysvar data is too short")
        values = ", ".join(f"{v}LL" for v in _CLOCK.unpack_from(sysvars["clock"]))
        lines.append(f"{{ struct sbpf_runtime_clock clock = {{{values}}};"
                     " sbpf_runtime_set_clock(&clock); }")
    return lines


def generate(
    message: SymbolicMessage,
    program_id: bytes,
    *,
    record_calls: bool = False,
    data_bytes: Optional[int] = EXPORT_DATA_CAP,
) -> str:
    """Emit a complete KLEE harness C source for this symbolic message."""
    layout = build_layout(message, program_id)
    lines: list[str] = []
    add = lines.append

    add("#include <stdint.h>")
    add("#include <string.h>")
    add("#include <klee/klee.h>")
    add('#include "asset_model.h"')
    add("extern uint64_t bpf_main(void *register_context, uint64_t size);")
    add(f"static const uint8_t template_bytes[{len(layout.template)}] = {{"
        f"{_c_bytes(layout.template)}}};")
    add("int main(void) {")
    add(f"  _Alignas(8) static uint8_t input[{len(layout.template)}];")
    add("  memcpy(input, template_bytes, sizeof(input));")

    # KLEE only makes a whole allocation symbolic, never an interior slice, so
    # each field is a fresh symbolic object, optionally constrained, then copied
    # into the input buffer with a byte-store loop. A memcpy here would be an
    # external call that concretizes the symbolic source, so the loop is
    # required to keep the input actually symbolic.
    for i, field in enumerate(message.symbolic):
        offset, size = _field_region(layout, message.model, program_id, field)
        add(f"  {{ uint8_t sym{i}[{size}];")
        add(f'    klee_make_symbolic(sym{i}, {size}, "{field.name}");')
        for line in _constraint_lines(f"sym{i}", size, message.constraints_for(field), i):
            add("    " + line)
        add(f"    for (unsigned j = 0; j < {size}; ++j) input[{offset} + j] = sym{i}[j]; }}")

    add("  sbpf_runtime_initialize();")
    for line in _sysvar_lines(message.sysvars):
        add("  " + line)
    # PDA oracle: sol_try_find_program_address succeeds only for hashes in this
    # set (the model skips the on-curve check), and a program only ever derives
    # addresses it was handed, so the instruction's accounts are the candidates.
    keys = list(dict.fromkeys(a.key for a in layout.accounts))[:32]
    words = ",".join(
        "{{" + ",".join(f"{int.from_bytes(k[i:i + 8], 'little')}ULL" for i in range(0, 32, 8)) + "}}"
        for k in keys
    )
    add(f"  static const struct pubkey pda_keys[{len(keys)}] = {{{words}}};")
    add(f"  pda_oracle_install(pda_keys, {len(keys)});")
    # Whole-program lift: bpf_main's first argument IS r1 (the serialized input
    # pointer). Unlike the function-pc lift, there is no register-array prologue.
    add("  uint64_t return_value = bpf_main((void *)(uintptr_t)input, sizeof(input));")
    add("  uint64_t return_out;")
    add('  klee_make_symbolic(&return_out, sizeof(return_out), "return_value");')
    add("  klee_assume(return_out == return_value);")
    add("  { uint8_t log_out[SBPF_LOG_TAIL_BYTES];")
    add('    klee_make_symbolic(log_out, SBPF_LOG_TAIL_BYTES, "log");')
    add("    for (unsigned i = 0; i < SBPF_LOG_TAIL_BYTES; ++i)")
    add("      klee_assume(log_out[i] == (uint8_t)sbpf_log_tail[i]); }")

    for account in layout.accounts:
        cap = account.data_length if data_bytes is None else data_bytes
        export = min(account.data_length, cap)
        add(f"  {{ uint64_t lamports_out;")
        add(f"    memcpy(&lamports_out, input + {account.lamports_offset}, 8);")
        add(f"    uint64_t lamports_export; klee_make_symbolic(&lamports_export,"
            f" 8, \"account{account.index}.lamports_after\");")
        add("    klee_assume(lamports_export == lamports_out); }")
        if export > 0:
            add(f"  {{ uint8_t data_out[{export}];")
            add(f"    memcpy(data_out, input + {account.data_offset}, {export});")
            add(f"    klee_make_symbolic(data_out, {export},"
                f" \"account{account.index}.data_after\");")
            add(f"    for (unsigned i = 0; i < {export}; ++i)")
            add(f"      klee_assume(data_out[i] == input[{account.data_offset} + i]); }}")

    if record_calls:
        add("  (void)sbpf_runtime_recorded_calls();")
    add("  return 0;")
    add("}")
    return "\n".join(lines) + "\n"
