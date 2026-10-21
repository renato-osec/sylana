# Deciphered — program complexity/decompilation map

The default view for a whole sBPF program: a squarified treemap where every
function is a block **sized by complexity** and **colored grey→green by how
confidently sylana can lift it** ("deciphered"). Click a function to zoom into
its own basic blocks; the headline **Deciphered %** is the complexity-weighted
average across all functions.

## Regenerate for any program

```
# inside runtime/shell.nix (needs sbpf-normalize on PATH or via --normalize)
python3 viz/extract.py path/to/program.so viz/owner_check.json \
  --normalize normalize/target/release/sbpf-normalize

# inline the JSON into the standalone viewer
python3 - <<'PY'
import pathlib
tpl=pathlib.Path("viz/index.template.html").read_text()
data=pathlib.Path("viz/owner_check.json").read_text().strip()
pathlib.Path("viz/index.html").write_text(tpl.replace("__DATA__", data))
PY
```

`index.html` is fully self-contained (data embedded) — open it or publish it.

## Files
- `extract.py` — normalize a `.so`, emit per-function `{size, complexity,
  branches, calls, callx, deciphered, blocks[]}` JSON. The `deciphered` score is
  a documented heuristic (indirect-dispatch + branch density); swap
  `deciphered_score()` for real KLEE coverage without touching the viewer.
- `index.template.html` — the viewer, with a `__DATA__` placeholder.
- `index.html` — generated: template + embedded data (owner-check example).
- `owner_check.json` — extracted model for `examples/owner-check`.
