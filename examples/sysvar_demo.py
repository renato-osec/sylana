"""Demonstrate sysvar reads via the syscall path.

Handler 5 (check_clock) reads Clock::get() and Rent::get() and transfers 1
lamport treasury -> recipient only if they look sane. The canonical sysvar
values (slot=100, rent>0) make the read succeed and the transfer happen, so a
program that reads sysvars now simulates cleanly.

Usage:
  python sysvar_demo.py path/to/owner_check_test.so
"""

from __future__ import annotations

import sys

from solders.account import Account
from solders.hash import Hash
from solders.instruction import CompiledInstruction
from solders.message import Message
from solders.pubkey import Pubkey

import sylana

PROGRAM = Pubkey(bytes([7]) + bytes(31))
TREASURY = Pubkey.new_unique()
RECIPIENT = Pubkey.new_unique()


def main(elf_path: str) -> None:
    keys = [PROGRAM, TREASURY, RECIPIENT]
    ix = CompiledInstruction(program_id_index=0, accounts=bytes([1, 2]), data=bytes([5]))
    msg = Message.new_with_compiled_instructions(1, 0, 0, keys, Hash.default(), [ix])
    accounts = {
        TREASURY: Account(lamports=100, data=b"", owner=PROGRAM, executable=False, rent_epoch=0),
        RECIPIENT: Account(lamports=10, data=b"", owner=PROGRAM, executable=False, rent_epoch=0),
    }
    sm = sylana.to_symbolic(msg, accounts=accounts)
    elf = sylana.SymbolicElf.load(elf_path, program_id=bytes(PROGRAM))
    result = elf.simulate_full_tx(sm)
    print(f"{len(result.paths)} path(s)")
    for n, path in enumerate(result.paths):
        print(f"  path {n}: ok={path.succeeded} return=0x{path.return_value:x}")
        for a in path.accounts_after:
            print(f"    {Pubkey(bytes(a.key))} lamports={a.lamports}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
