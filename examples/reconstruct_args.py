"""Reconstruct the actual arguments to the entrypoint's handler on one path.

withdraw_vulnerable(program_id: &Pubkey, accounts: &[AccountInfo]) reads its
arguments out of the serialized input buffer. We open a live session and read
that buffer back, concretized under the path constraints, to show the real
program_id and per-account fields. record.owner and record.data are symbolic
here, so their values are one satisfying assignment for the shown path.

Usage:
  python reconstruct_args.py path/to/owner_check_test.so
"""

from __future__ import annotations

import sys

import sylana
from sylana.harness import build_layout
import local_demo as demo


def main(elf_path: str) -> None:
    sm = sylana.to_symbolic(
        demo.build_message(),
        symbolic=[demo.sym.account_owner(1), demo.sym.account_data(1, byte_range=(0, 8))],
        accounts=demo.build_accounts(),
    )
    layout = build_layout(sm, bytes(demo.PROGRAM))
    want = len(layout.template)
    elf = sylana.SymbolicElf.load(elf_path, program_id=bytes(demo.PROGRAM))

    with elf.simulate_session(sm) as sess:
        # Two globals share the buffer size (const template + live input); the
        # live one is the buffer that actually holds symbolic bytes.
        candidates = [b for b, s in sess.objects(0) if s == want]
        owner_off = layout.accounts[0].owner_offset
        base = next(
            (b for b in candidates if sess.read_symbolic(b + owner_off, 32)["is_symbolic"]),
            candidates[0],
        )
        program_id = sess.read(base + want - 32, 32)
        print("program_id:", program_id.hex())
        for a in layout.accounts:
            owner_addr = base + a.owner_offset
            owner = sess.read(owner_addr, 32)
            osym = sess.read_symbolic(owner_addr, 32)
            lamports = int.from_bytes(sess.read(base + a.lamports_offset, 8), "little")
            tag = f" SYMBOLIC dep={osym['arrays']}" if osym["is_symbolic"] else " concrete"
            print(f"account[{a.index}] owner={owner[:8].hex()}{tag} lamports={lamports}")
            if a.data_length >= 8:
                amt_addr = base + a.data_offset
                amount = int.from_bytes(sess.read(amt_addr, 8), "little")
                asym = sess.read_symbolic(amt_addr, 8)
                print(f"   amount witness={amount} symbolic={asym['is_symbolic']} "
                      f"dep={asym['arrays']}")
                print(f"   amount expr: {sess.expr(amt_addr, 8)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
