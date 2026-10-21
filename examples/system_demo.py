"""Demonstrate the System-program CPI model.

Handler 4 (system_transfer_vulnerable) moves lamports payer -> recipient through
a CPI to the System program, with the amount taken from the untrusted record.
Before the System model existed this stopped with SylanaUnsupportedCpi; now it
simulates and the balances move.

Usage:
  python system_demo.py path/to/owner_check_test.so
"""

from __future__ import annotations

import sys

from solders.account import Account
from solders.hash import Hash
from solders.instruction import CompiledInstruction
from solders.message import Message
from solders.pubkey import Pubkey

import sylana
from sylana import sym

PROGRAM = Pubkey(bytes([7]) + bytes(31))   # analyzed program (must not be System)
RECORD = Pubkey.new_unique()
PAYER = Pubkey.new_unique()
RECIPIENT = Pubkey.new_unique()
SYSTEM = Pubkey.default()                   # all zeros = System program


def build():
    keys = [PROGRAM, RECORD, PAYER, RECIPIENT, SYSTEM]
    ix = CompiledInstruction(program_id_index=0, accounts=bytes([1, 2, 3, 4]), data=bytes([4]))
    msg = Message.new_with_compiled_instructions(1, 0, 1, keys, Hash.default(), [ix])
    accounts = {
        RECORD: Account(lamports=1, data=(50).to_bytes(8, "little"), owner=PROGRAM, executable=False, rent_epoch=0),
        PAYER: Account(lamports=100, data=b"", owner=SYSTEM, executable=False, rent_epoch=0),
        RECIPIENT: Account(lamports=10, data=b"", owner=SYSTEM, executable=False, rent_epoch=0),
        SYSTEM: Account(lamports=1, data=b"", owner=Pubkey.default(), executable=True, rent_epoch=0),
    }
    return msg, accounts


def main(elf_path: str) -> None:
    msg, accounts = build()
    sm = sylana.to_symbolic(msg, symbolic=[sym.account_data(1, byte_range=(0, 8))], accounts=accounts)
    elf = sylana.SymbolicElf.load(elf_path, program_id=bytes(PROGRAM))
    result = elf.simulate_full_tx(sm, data_bytes=None)
    print(f"{len(result.paths)} path(s)")
    for n, path in enumerate(result.paths):
        amt = path.witness.get("account1.data[0:8]")
        print(f"  path {n}: ok={path.succeeded} return=0x{path.return_value:x} "
              f"amount={amt.as_int() if amt else '-'}")
        for a in path.accounts_after:
            print(f"    {Pubkey(bytes(a.key))} lamports={a.lamports}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
