# klee-session: a libKLEE fork exposing per-object symbolic memory

`simulate_full_tx` extracts post-state through witnesses because a one-shot
`klee` run exits and its memory is gone. This fork keeps the memory live and
queryable by address, backing `SymbolicElf.simulate_session`.

## What it is

A forked KLEE that builds an extra resident tool, `klee-session`. It reuses
nixpkgs' KLEE build (LLVM 16 and all solver deps) and adds, via `fork.nix`'s
`postPatch`:

- `tools/klee-session/` (this `main.cpp` + `CMakeLists.txt`), registered in
  `tools/CMakeLists.txt`.
- One public `Executor` method, `readConcrete`, injected by
  `apply-executor-edits.sh`. It resolves a concrete address in a kept
  `AddressSpace`, reads the byte `Expr`, and concretizes it with the Executor's
  own solver under the kept `ConstraintSet`.

The tool runs the linked module, and in `processTestCase` snapshots each
terminated state's `addressSpace` + `constraints` (both copyable; the
`MemoryObject`s stay valid because the Executor stays alive). It then serves a
line protocol on stdin until EOF:

```
count               -> number of snapshots
objects <i>         -> "<hexbase> <size>" per mapped object, then "end"
read <i> <hexaddr> <len>  -> "ok <hex>" | "unmapped"
quit
```

Because the process holds the states, memory is queryable for the process's
lifetime; closing stdin frees them. `SimulationSession` owns the process and
tears it down on close / context exit / GC.

## Build

```sh
nix-build --impure fork.nix -o result-klee-session
```

Produces `result-klee-session/bin/klee-session`. sylana discovers it
automatically (or set `SYLANA_KLEE_SESSION`). It is a full KLEE build from
source, so the first build takes several minutes.

## Use from Python

```python
with elf.simulate_session(sm) as sess:
    for base, size in sess.objects(0):
        ...
    data = sess.read(address, length, snapshot=0)   # concretized bytes, or None
    ptr = sess.deref(address, snapshot=0)            # 8-byte LE pointer
```
