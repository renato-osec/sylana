# sylana

Fast symbolic execution of deployed Solana sBPF programs. Point it at a `.so`,
say which parts of a transaction the solver may vary, and get back the concrete
inputs that reach each program outcome.

It lifts the compiled program to LLVM IR and runs KLEE over it

## Build

```sh
rustup default stable   # solana-sbpf needs rustc >= 1.84
nix develop             
./build.sh              
```

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

- `owner-check/` a synthetic safe-vs-vulnerable program and its harnesses
- `fetch_and_simulate.py` any real mainnet tx, fetched at its slot

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
  `Transfer`/`TransferChecked` are modeled as of now
- Symbolic 128-bit arithmetic (wide integer multiplies, u256 math) is pretty slow atm
- The pure-Python model (`to_symbolic`, message/account layout, KTEST parsing)
  works with no engine; symbolic runs need `./build.sh` and KLEE.

## License

[0BSD](LICENSE): use it for anything, no attribution required. KLEE (NCSA) and
llvmbpf are fetched at build time under their own licenses, and not vendored here.
