# examples

Every example here runs against `owner-check/`, a small synthetic Solana
program with matched safe and vulnerable handlers, built for the purpose. Build
it first (see `owner-check/README.md`), then pass its `.so` to any script.

- `local_demo.py` — fully offline: leave a record's owner and amount symbolic,
  ask whether the vulnerable withdrawal is reachable. No RPC.
- `system_demo.py` — a lamport transfer through the System-program CPI model.
- `sysvar_demo.py` — a handler that reads `Clock`/`Rent` via the syscall path.
- `query_memory.py` — open a live session and read the terminated state's
  memory by address.
- `scan_symbolic.py` — walk the address space and report where the symbolic
  inputs ended up.
- `reconstruct_args.py` — recover a handler's real arguments on one path.
- `fetch_and_simulate.py` — point it at any mainnet transaction and its
  program `.so`; it fetches the touched accounts at that slot and simulates.
