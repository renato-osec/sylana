"""Integration check for simulate_full_tx on the owner-check program.

Runs the real normalize->emit->compile->link->klee pipeline (needs the nix
shell toolchain). Validates bug-1 fix: the whole-program entrypoint dispatches
and executes instead of returning NotEnoughAccountKeys (0xb00000000).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sylana.elf import SymbolicElf
from sylana.model import AccountInput, Instruction, MessageModel
from sylana.symbolic import SymbolicMessage, SymbolicField, FieldKind

PID = b"\x42" + b"\x00" * 31
REC = b"\x01" + b"\x00" * 31
TRE = b"\x02" + b"\x00" * 31
RCP = b"\x03" + b"\x00" * 31


def message(selector: int, amount: int, symbolic_amount: bool) -> SymbolicMessage:
    keys = (REC, TRE, RCP, PID)
    ix = Instruction(program_id_index=3, account_indices=(0, 1, 2),
                     data=bytes([selector]))
    model = MessageModel(
        version="legacy", account_keys=keys,
        num_required_signatures=1, num_readonly_signed=0, num_readonly_unsigned=1,
        recent_blockhash=b"\x00" * 32, instructions=(ix,),
    )
    accounts = {
        REC: AccountInput(key=REC, owner=PID, data=amount.to_bytes(8, "little")),
        TRE: AccountInput(key=TRE, owner=PID, lamports=100, is_writable=True),
        RCP: AccountInput(key=RCP, owner=PID, lamports=10, is_writable=True),
    }
    symbolic = ()
    if symbolic_amount:
        symbolic = (SymbolicField(FieldKind.ACCOUNT_DATA, 0, (0, 8)),)
    return SymbolicMessage(model=model, symbolic=symbolic, accounts=accounts)


def main() -> None:
    elf = SymbolicElf.load(
        Path(__file__).resolve().parents[2]
        / "examples/owner-check/target/deploy/owner_check_test.so",
        program_id=PID,
    )
    # Concrete: withdraw_vulnerable moves `amount` lamports; expect success.
    res = elf.simulate_full_tx(message(0, 7, symbolic_amount=False))
    p = res.paths[0]
    print(f"[concrete sel0] return=0x{p.return_value:x} succeeded={p.succeeded}")
    after = {a.key: a.lamports for a in p.accounts_after}
    print(f"  treasury={after.get(TRE)} recipient={after.get(RCP)}")
    assert p.succeeded, f"expected success, got 0x{p.return_value:x}"
    assert after.get(TRE) == 93 and after.get(RCP) == 17, "lamports not moved by 7"

    # Symbolic amount: expect multiple feasible paths (transfer vs insufficient).
    res2 = elf.simulate_full_tx(message(0, 0, symbolic_amount=True))
    rets = sorted(f"0x{p.return_value:x}" for p in res2.paths)
    print(f"[symbolic sel0] {len(res2.paths)} path(s): {rets}")
    assert any(p.succeeded for p in res2.paths), "no successful path with symbolic amount"

    print("INTEGRATION OK")


if __name__ == "__main__":
    main()
