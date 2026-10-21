# sylana

Fast symbolic execution of deployed Solana sBPF programs. Point it at a `.so`,
say which parts of a transaction the solver may vary, and get back the concrete
inputs that reach each program outcome.

It lifts the compiled program to LLVM IR and runs KLEE over it. A small Python
layer lets you describe the transaction with `solders`/`solana` types, so you
never touch the IR.

## Build

```sh
rustup default stable   # solana-sbpf needs rustc >= 1.84
nix develop             # or nix-shell: LLVM 16, KLEE 3.1, cmake, python, uv
./build.sh              # normalize/ (system rust) + emitter/ (nix)
```

KLEE is pinned as a git dependency: `flake.nix` and `shell.nix` fix the one
nixpkgs revision that still ships LLVM 16 + KLEE 3.1, so nothing is installed by
hand and the shell reproduces anywhere.

## Use

```python
import sylana
from sylana import sym

elf = sylana.SymbolicElf.load("program.so", program_id=bytes(pubkey))
sm = sylana.to_symbolic(tx, symbolic=[sym.instruction_data(0)], accounts=snapshot)

for path in elf.simulate_full_tx(sm).paths:
    print(path.return_value, path.succeeded)
```

Runnable examples in `examples/` (see `examples/README.md`):

- `owner-check/` — a synthetic safe-vs-vulnerable program and its harnesses
- `local_demo.py` — a fully offline run against it, nothing to fetch
- `fetch_and_simulate.py` — any real mainnet tx, fetched at its slot

## Layout

```
normalize/     relocate + canonicalize an sBPF ELF (Rust: sbpf-normalize)
emitter/       lift normalized bytecode to LLVM IR (C++ over a pinned llvmbpf)
runtime/       KLEE syscall/account/asset models + the pinned LLVM 16 / KLEE shell
klee-session/  a libKLEE fork that keeps a state's symbolic memory queryable by address
python/        the sylana package: the public API and the pipeline that drives the engine
```

## Notes

- Unmodeled CPIs raise `SylanaUnsupportedCpi`; only SPL Token / Token-2022
  `Transfer`/`TransferChecked` are modeled today.
- Symbolic 128-bit arithmetic (wide integer multiplies, u256 math) hits the
  solver wall; bound the field or keep it concrete. Z3 and STP both bit-blast it.
- The pure-Python model (`to_symbolic`, message/account layout, KTEST parsing)
  works with no engine; symbolic runs need `./build.sh` and KLEE.

## License

[0BSD](LICENSE): use it for anything, no attribution required. KLEE (NCSA) and
llvmbpf are fetched at build time under their own licenses, not vendored here.
