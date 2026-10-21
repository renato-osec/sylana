"""Scan a live session's address space for objects that hold symbolic bytes.

Answers "where did the symbolic inputs end up" by walking every mapped object
and reporting which ones still contain symbolic bytes and the arrays they
depend on.

Usage:
  python scan_symbolic.py path/to/owner_check_test.so
"""

from __future__ import annotations

import sys

import sylana
import local_demo as demo


def main(elf_path: str) -> None:
    sm = sylana.to_symbolic(
        demo.build_message(),
        symbolic=[demo.sym.account_owner(1), demo.sym.account_data(1, byte_range=(0, 8))],
        accounts=demo.build_accounts(),
    )
    elf = sylana.SymbolicElf.load(elf_path, program_id=bytes(demo.PROGRAM))
    with elf.simulate_session(sm) as sess:
        print("snapshots:", sess.count())
        found = 0
        for base, size in sess.objects(0):
            if size > (1 << 24):
                continue
            n = min(size, 512)
            rs = sess.read_symbolic(base, n, snapshot=0)
            if rs and rs["is_symbolic"]:
                found += 1
                print(f"0x{base:x} size={size} symbolic_bytes={rs['mask'][:n].count('1')} "
                      f"arrays={rs['arrays']}")
        print("objects with symbolic bytes:", found)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
