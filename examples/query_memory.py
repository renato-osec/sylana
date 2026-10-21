"""Open a live KLEE session and query memory after execution.

Unlike simulate_full_tx, which returns per-path witnesses, a session keeps the
terminated state's per-object symbolic memory resident so you can read any
address on demand. The state lives until the session is closed.

Usage:
  python query_memory.py path/to/owner_check_test.so
"""

from __future__ import annotations

import sys

import sylana
from sylana.harness import build_layout
import local_demo as demo


def main(elf_path: str) -> None:
    sm = sylana.to_symbolic(
        demo.build_message(),
        symbolic=[demo.sym.account_data(1, byte_range=(0, 8))],
        accounts=demo.build_accounts(),
    )
    elf = sylana.SymbolicElf.load(elf_path, program_id=bytes(demo.PROGRAM))

    # The serialized entrypoint input is a global of exactly this size.
    want = len(build_layout(sm, bytes(demo.PROGRAM)).template)

    with elf.simulate_session(sm) as sess:
        print("snapshots:", sess.count())
        objects = sess.objects(0)
        print("mapped objects:", len(objects))
        match = [o for o in objects if o[1] == want]
        base = match[0][0]
        print(f"input buffer base=0x{base:x} size={want}")
        # its first u64 is the account count the program received
        count = sess.read(base, 8, snapshot=0)
        print(f"  account count = {int.from_bytes(count, 'little')}")
        # bytes 8.. begin the first account record (NON_DUP_MARKER 0xff)
        head = sess.read(base + 8, 4, snapshot=0)
        print(f"  first account header = {head.hex()}")
    # session (and its klee-session process) is torn down here


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
