# owner-check example

A deliberately mixed program: `withdraw_safe`/`withdraw_vulnerable` and the two
token variants differ only in whether they check the withdrawal record's owner
before trusting its amount. Build it with `cargo-build-sbf`, then point sylana
at the resulting `target/deploy/owner_check_test.so`.

`harnesses/` holds the original hand-written KLEE probes the pipeline grew from.
They are kept as worked references; the Python API generates equivalent
harnesses automatically from a symbolic message.

Each probe is written for one lift mode: whole-program entrypoint (r1 = input
pointer), the `process_instruction` dispatcher (`-DPROCESS_INSTRUCTION_SELECTOR`),
or a single leaf function. `run_harnesses.sh` builds and runs each in its correct
mode and checks the witness; run it inside `runtime/shell.nix`.
