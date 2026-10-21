"""Self-contained sylana demo: no RPC, just a synthetic owner-check transaction.

Builds a transaction for the example program's `withdraw_vulnerable` path,
leaves the withdrawal record's owner and amount symbolic, and asks whether the
lamport transfer is reachable for a record the program does not own.

Usage:
  python local_demo.py path/to/owner_check_test.so
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

PROGRAM = Pubkey.from_string("11111111111111111111111111111111")
RECORD = Pubkey.new_unique()
TREASURY = Pubkey.new_unique()
RECIPIENT = Pubkey.new_unique()
ATTACKER = Pubkey.new_unique()


def build_message() -> Message:
    keys = [PROGRAM, RECORD, TREASURY, RECIPIENT]
    # instruction 0 (withdraw_vulnerable), accounts: record, treasury, recipient
    ix = CompiledInstruction(program_id_index=0, accounts=bytes([1, 2, 3]), data=bytes([0]))
    return Message.new_with_compiled_instructions(1, 0, 1, keys, Hash.default(), [ix])


def build_accounts() -> dict[Pubkey, Account]:
    amount = (7).to_bytes(8, "little")  # concrete initial record amount
    return {
        RECORD: Account(lamports=1, data=amount, owner=ATTACKER, executable=False, rent_epoch=0),
        TREASURY: Account(lamports=100, data=b"", owner=PROGRAM, executable=False, rent_epoch=0),
        RECIPIENT: Account(lamports=10, data=b"", owner=ATTACKER, executable=False, rent_epoch=0),
    }


def main(elf_path: str) -> None:
    message = build_message()
    accounts = build_accounts()

    # symbolic part: the record's owner and its 8-byte amount field
    sm = sylana.to_symbolic(
        message,
        symbolic=[sym.account_owner(1), sym.account_data(1, byte_range=(0, 8))],
        accounts=accounts,
    )

    elf = sylana.SymbolicElf.load(elf_path, program_id=bytes(PROGRAM))
    result = elf.simulate_full_tx(sm)

    print(f"{len(result.paths)} feasible path(s)")
    for n, path in enumerate(result.paths):
        owner = path.witness.get("account1.owner")
        owner_hex = owner.concrete.hex()[:16] if owner and owner.concrete else "-"
        # The symbolic amount (record data[0:8]) is what actually forks the run.
        amount = path.witness.get("account1.data[0:8]")
        amount_val = (
            int.from_bytes(amount.concrete, "little")
            if amount and amount.concrete is not None
            else "-"
        )
        print(f"  path {n}: ok={path.succeeded} return=0x{path.return_value:x}"
              f" record_owner~{owner_hex} amount={amount_val}")
        for account in path.accounts_after:
            print(f"    {Pubkey(bytes(account.key))} lamports={account.lamports}")
        for clause in path.constraints:
            print(f"    constraint: {clause}")

    # Only #[no_mangle] names survive; use elf.functions to see them, or a PC.
    print("\ncalls to withdraw_vulnerable:")
    for call in elf.get_function_call_args(sm, "withdraw_vulnerable"):
        print(f"  pc={call.pc} args={[a.hex() for a in call.args]}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
