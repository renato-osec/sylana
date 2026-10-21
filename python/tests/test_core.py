"""Tests for the toolchain-independent core: model, symbolic, harness, ktest."""

from __future__ import annotations

import struct

import pytest

from sylana import FieldKind, SymbolicMessage, sym, to_symbolic
from sylana.harness import DATA_OFFSET, LAMPORTS_OFFSET, build_layout, generate
from sylana.ktest import constraints_from_kquery, parse
from sylana.model import Instruction, MessageModel, to_model
from sylana.pipeline import KleeRun, rodata_source

PROGRAM = bytes([1]) + bytes(31)
RECORD = bytes([2]) + bytes(31)


def make_model() -> MessageModel:
    return MessageModel(
        version="legacy",
        account_keys=(PROGRAM, RECORD),
        num_required_signatures=1,
        num_readonly_signed=0,
        num_readonly_unsigned=1,
        recent_blockhash=bytes(32),
        instructions=(
            Instruction(program_id_index=0, account_indices=(1,), data=b"\x00\x07"),
        ),
    )


# --- solders-style adapter (no solders installed) ---

class _Key:
    def __init__(self, raw: bytes) -> None:
        self._raw = raw

    def __bytes__(self) -> bytes:
        return self._raw


class _Header:
    num_required_signatures = 1
    num_readonly_signed_accounts = 0
    num_readonly_unsigned_accounts = 1


class _Ix:
    program_id_index = 0
    accounts = bytes([1])
    data = b"\x03\x01"


class _Message:
    account_keys = [_Key(PROGRAM), _Key(RECORD)]
    header = _Header()
    recent_blockhash = _Key(bytes(32))
    instructions = [_Ix()]


class _Tx:
    def message(self):
        return _Message()


def test_to_model_from_solders_like():
    model = to_model(_Tx())
    assert model.account_keys == (PROGRAM, RECORD)
    assert model.num_readonly_unsigned == 1
    assert model.instructions[0].account_indices == (1,)
    assert model.instructions[0].data == b"\x03\x01"
    assert model.program_id(0) == PROGRAM


def test_to_symbolic_default_is_concrete():
    message = to_symbolic(make_model())
    assert isinstance(message, SymbolicMessage)
    assert message.is_concrete
    assert message.field_names() == ()


def test_to_symbolic_selects_fields():
    message = to_symbolic(
        make_model(),
        symbolic=[sym.instruction_data(0), sym.account_owner(1)],
    )
    assert not message.is_concrete
    names = message.field_names()
    assert "ix0.data" in names
    assert "account1.owner" in names
    kinds = {f.kind for f in message.symbolic}
    assert FieldKind.INSTRUCTION_DATA in kinds and FieldKind.ACCOUNT_OWNER in kinds


def test_to_symbolic_rejects_out_of_range():
    with pytest.raises(IndexError):
        to_symbolic(make_model(), symbolic=[sym.account_key(9)])


def test_build_layout_offsets():
    message = to_symbolic(make_model())
    layout = build_layout(message, PROGRAM)
    # one account (index 1) is referenced by the instruction
    assert len(layout.accounts) == 1
    account = layout.accounts[0]
    assert account.index == 1
    assert account.lamports_offset == account.start + LAMPORTS_OFFSET
    assert account.data_offset == account.start + DATA_OFFSET
    # buffer begins with the little-endian account count
    assert layout.template[:8] == (1).to_bytes(8, "little")
    # program id is appended at the end
    assert layout.template[-32:] == PROGRAM


def test_generate_marks_symbolic_and_exports():
    message = to_symbolic(make_model(), symbolic=[sym.instruction_data(0)])
    source = generate(message, PROGRAM)
    # symbolic input is a fresh object stored in byte by byte (not memcpy'd,
    # which KLEE would concretize; not an interior make_symbolic slice)
    assert "klee_make_symbolic(sym0" in source
    assert "= sym0[j];" in source
    assert '"ix0.data"' in source
    assert '"return_value"' in source
    assert "account1.lamports_after" in source
    # whole-program lift: the input buffer is bpf_main's first arg (r1), not a
    # register-array context (which would leave r1 = &array and read zeros).
    assert "bpf_main((void *)(uintptr_t)input, sizeof(input))" in source
    # the instruction's accounts seed the PDA oracle (RECORD = 2 + zeros)
    assert "pda_keys[1] = {{{2ULL,0ULL,0ULL,0ULL}}}" in source
    assert "pda_oracle_install(pda_keys, 1);" in source
    assert 'klee_make_symbolic(log_out, SBPF_LOG_TAIL_BYTES, "log");' in source


def test_sysvars_override_the_runtime_defaults():
    rent = struct.pack("<QdB", 2540, 2.0, 50)
    clock = struct.pack("<QqQQq", 448081345, 1, 2, 3, 1700000000)
    message = to_symbolic(make_model(), sysvars={"rent": rent, "clock": clock})
    source = generate(message, PROGRAM)
    assert "struct sbpf_runtime_rent rent = {2540ULL, 2.0, 50}; sbpf_runtime_set_rent(&rent);" in source
    assert "struct sbpf_runtime_clock clock = {448081345LL, 1LL, 2LL, 3LL, 1700000000LL};" in source
    assert "sbpf_runtime_set_rent" not in generate(to_symbolic(make_model()), PROGRAM)


def test_scalar_constraint_emits_assume():
    sm = to_symbolic(make_model(), assume=[sym.instruction_data(0).le(3)])
    assert "ix0.data" in sm.field_names()  # constrained field auto-symbolic
    source = generate(sm, PROGRAM)
    assert "klee_assume(_c" in source and "<= 3ULL" in source


def test_pubkey_constraint_emits_byte_compare():
    sm = to_symbolic(make_model(), assume=[sym.account_owner(1).ne(RECORD)])
    source = generate(sm, PROGRAM)
    assert "klee_assume(!(" in source


def _ktest_blob(objects: list[tuple[str, bytes]]) -> bytes:
    out = b"KTEST" + struct.pack(">I", 3)
    out += struct.pack(">I", 0)  # numArgs
    out += struct.pack(">I", 0) + struct.pack(">I", 0)  # symArgvs, symArgvLen
    out += struct.pack(">I", len(objects))
    for name, data in objects:
        raw = name.encode()
        out += struct.pack(">I", len(raw)) + raw
        out += struct.pack(">I", len(data)) + data
    return out


def test_ktest_roundtrip():
    blob = _ktest_blob([
        ("return_value", (0).to_bytes(8, "little")),
        ("ix0.data", b"\x03\x2a"),
        ("account1.lamports_after", (42).to_bytes(8, "little")),
    ])
    ktest = parse(blob)
    assert ktest.version == 3
    values = ktest.as_dict()
    assert values["ix0.data"] == b"\x03\x2a"
    assert int.from_bytes(values["account1.lamports_after"], "little") == 42


def test_constraints_from_kquery_keeps_path_condition_drops_exports():
    text = """array account1.data[0:8][8] : w32 -> w8 = symbolic
array return_value[8] : w32 -> w8 = symbolic
(query [(Eq false
             (Ule (ReadLSB w64 0 account1.data[0:8])
                  100))
         (Eq 25769803776
             (ReadLSB w64 0 return_value))]
        false)
"""
    clauses = constraints_from_kquery(text)
    # the branch decision survives, collapsed to one line...
    assert clauses == ("(Eq false (Ule (ReadLSB w64 0 account1.data[0:8]) 100))",)
    # ...and the witness-export equality (return_value) is dropped
    assert not any("return_value" in c for c in clauses)


def test_completed_ktests_exclude_errored_paths():
    from pathlib import Path
    run = KleeRun(
        out_dir=Path("ko"),
        ktests=[Path("ko/test000001.ktest"), Path("ko/test000002.ktest")],
        errors=["test000002.cpi.err"],
    )
    assert run.completed_ktests() == [Path("ko/test000001.ktest")]


def test_rodata_source_places_regions_at_the_guest_address():
    source = rodata_source(
        "rodata_vm_addr=0x100000120\nrodata_region.end=3\nrodata_region.end=5\n",
        b"\x01\x02\x03\x04\x05",
    )
    assert "sbpf_program_rodata_vm_addr = 4294967584ULL" in source
    assert "ends[] = {3,5}" in source and "region_count = 2" in source
    assert "bytes[] = {1,2,3,4,5}" in source
