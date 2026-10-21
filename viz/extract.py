#!/usr/bin/env python3
"""Extract a per-function complexity + decipher-confidence model from a program.

Runs sbpf-normalize on a .so (or reads an existing normalized .bin + .map) and
emits the JSON the treemap viewer consumes: every function sized by complexity,
scored by how confidently sylana can lift it, split into basic blocks for the
zoom view. The `deciphered` score is a documented, swappable heuristic -- wire it
to real KLEE coverage later without touching the viewer.
"""

from __future__ import annotations

import json
import struct
import subprocess
import sys
from pathlib import Path

# eBPF opcode classes (low 3 bits) and jump op-codes (high nibble).
CLASS = lambda op: op & 0x07
JMP, JMP32, LD = 0x05, 0x06, 0x00
COND_OPS = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0xA, 0xB, 0xC, 0xD}  # JEQ..JSLE
CALL_STATIC, CALL_REG, EXIT, JA, LDDW = 0x85, 0x8D, 0x95, 0x05, 0x18


def decode(bin_bytes: bytes):
    """Yield (slot, opcode, dst, src, offset, imm), skipping LDDW's 2nd slot."""
    n = len(bin_bytes) // 8
    skip = False
    for i in range(n):
        if skip:
            skip = False
            yield i, None, 0, 0, 0, 0  # LDDW tail (not an instruction leader)
            continue
        op, regs, off, imm = struct.unpack_from("<BBhi", bin_bytes, i * 8)
        if op == LDDW:
            skip = True
        yield i, op, regs & 0xF, regs >> 4, off, imm


def parse_map(text: str):
    funcs, meta = [], {}
    for line in text.splitlines():
        if line.startswith("function."):
            head, _, tail = line.partition("=")
            pc = int(head.split(".", 1)[1])
            name = tail.split(",", 1)[1] if "," in tail else f"sub_{pc}"
            funcs.append((pc, name))
        elif "=" in line and "." not in line.split("=", 1)[0]:
            k, _, v = line.partition("=")
            meta[k] = v
    funcs.sort()
    return funcs, meta


def basic_blocks(instrs, base):
    """Split one function's decoded instrs into basic blocks. instrs is the list
    of (op, off) slots for [base, end); returns leader-relative block spans."""
    n = len(instrs)
    leaders = {0}
    for k, (op, off) in enumerate(instrs):
        if op is None:
            continue
        if CLASS(op) in (JMP, JMP32) and (op >> 4) in COND_OPS or op == JA:
            leaders.add(k + 1)          # fall-through / after a jump
            tgt = k + 1 + off
            if 0 <= tgt < n:
                leaders.add(tgt)         # branch target (intra-function only)
        elif op in (CALL_STATIC, CALL_REG, EXIT):
            leaders.add(k + 1)
    ordered = sorted(x for x in leaders if x < n)
    blocks = []
    for idx, start in enumerate(ordered):
        stop = ordered[idx + 1] if idx + 1 < len(ordered) else n
        span = instrs[start:stop]
        callx = sum(1 for op, _ in span if op == CALL_REG)
        cond = sum(1 for op, _ in span if op is not None
                   and CLASS(op) in (JMP, JMP32) and (op >> 4) in COND_OPS)
        kind = "dispatch" if callx else ("branch" if cond else "linear")
        # Block clarity: straight-line = clear; indirect dispatch = murky.
        dec = 1.0 - min(1.0, callx / 2) * 0.7 - min(1.0, cond / 4) * 0.2
        blocks.append({"start": base + start, "len": max(1, stop - start),
                       "kind": kind, "deciphered": round(max(0.08, dec), 3)})
    return blocks


def deciphered_score(size, cond, callx):
    """Decompilation-confidence heuristic in [0,1]; higher = greener.
    Straight-line leaf with no indirect dispatch -> ~1.0; a branchy indirect
    dispatcher -> low. Monotonic in the signals; swap for KLEE coverage later."""
    callx_pressure = min(1.0, callx / 3.0)
    branch_density = min(1.0, (cond / max(size, 1)) / 0.25)
    dec = 1.0 - 0.55 * callx_pressure - 0.30 * branch_density
    return round(max(0.1, min(1.0, dec)), 3)


def build_model(bin_bytes, funcs, meta):
    slots = list(decode(bin_bytes))          # index -> (i, op, dst, src, off, imm)
    total = len(slots)
    bounds = [(pc, name, (funcs[i + 1][0] if i + 1 < len(funcs) else total))
              for i, (pc, name) in enumerate(funcs)]
    out_funcs = []
    for pc, name, end in bounds:
        span = [(slots[k][1], slots[k][4]) for k in range(pc, min(end, total))]
        size = len(span)
        if size == 0:
            continue
        cond = sum(1 for op, _ in span if op is not None
                   and CLASS(op) in (JMP, JMP32) and (op >> 4) in COND_OPS)
        callx = sum(1 for op, _ in span if op == CALL_REG)
        calls = sum(1 for op, _ in span if op == CALL_STATIC)
        complexity = cond + 1
        out_funcs.append({
            "name": name, "pc": pc, "size": size,
            "complexity": complexity, "branches": cond,
            "calls": calls, "callx": callx,
            "deciphered": deciphered_score(size, cond, callx),
            "blocks": basic_blocks(span, pc),
        })
    tw = sum(f["complexity"] for f in out_funcs) or 1
    pct = sum(f["complexity"] * f["deciphered"] for f in out_funcs) / tw
    return {
        "program": meta.get("input", "program"),
        "sbpf_version": meta.get("sbpf_version", "?"),
        "instructions": total,
        "functions_count": len(out_funcs),
        "deciphered_pct": round(pct, 4),
        "functions": sorted(out_funcs, key=lambda f: -f["complexity"]),
    }


def main(argv):
    if len(argv) < 2:
        sys.exit("usage: extract.py PROGRAM.so [out.json] [--normalize BIN]")
    src = Path(argv[1])
    out = Path(argv[2]) if len(argv) > 2 and not argv[2].startswith("-") else None
    normalize = "sbpf-normalize"
    if "--normalize" in argv:
        normalize = argv[argv.index("--normalize") + 1]

    work = Path("/tmp") / f"viz-{src.stem}"
    work.mkdir(exist_ok=True)
    binp = work / "prog.bin"
    mp = subprocess.run([normalize, str(src), str(binp), "--summarize-log-formats"],
                        capture_output=True, text=True)
    if mp.returncode != 0:
        sys.exit(f"normalize failed: {mp.stderr}")
    funcs, meta = parse_map(mp.stdout)
    model = build_model(binp.read_bytes(), funcs, meta)
    text = json.dumps(model, indent=None)
    if out:
        out.write_text(text)
        print(f"wrote {out} : {model['functions_count']} funcs, "
              f"deciphered {model['deciphered_pct']*100:.1f}%")
    else:
        print(text)


if __name__ == "__main__":
    main(sys.argv)
