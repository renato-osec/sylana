#!/usr/bin/env bash
# Build and run each hand-written KLEE reference harness in its correct lift mode
# and report the KLEE witness each produces. Run inside runtime/shell.nix so
# clang/llvm/klee are on PATH.
#
# Three lift modes:
#   entry <selector> [defs]  whole-program lift; bpf_main's first arg is r1=input
#   disp  <selector|-> [defs] function-pc process_instruction; -DPROCESS_INSTRUCTION_SELECTOR
#                              ('-' for harnesses that hardcode the selector)
#   leaf  <function>         function-pc lift of a single leaf function
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
N="$ROOT/normalize/target/release/sbpf-normalize"
E="$ROOT/emitter/build/sbpf-llvm-emit"
SO="$ROOT/examples/owner-check/target/deploy/owner_check_test.so"
RT="$ROOT/runtime"
HD="$ROOT/examples/owner-check/harnesses"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
klee_inc="$(dirname "$(dirname "$(command -v klee)")")/include"
CF="-emit-llvm -c -g -O0 -U_FORTIFY_SOURCE -Xclang -disable-O0-optnone"
export NIX_HARDENING_ENABLE=
fails=0

# Lift the program (cached per key) into $T/<key>.bc.
lift() { # key  extra-normalize-args...
  local key="$1"; shift
  [ -f "$T/$key.bc" ] && return 0
  "$N" "$SO" "$T/$key.bin" "$@" --summarize-log-formats > "$T/$key.map" 2>/dev/null
  "$E" "$T/$key.bin" "$T/$key.bin.callx-targets" > "$T/$key.ll" 2> "$T/$key.emit.err"
  llvm-as "$T/$key.ll" -o "$T/$key.bc"
}

pc_of() { awk -F'[.=,]' -v fn="$1" '$1=="function" && $4==fn{print $2}' "$T/whole.map"; }

run_one() { # name mode arg defs
  local name="$1" mode="$2" arg="$3" defs="${4:-}" key bc
  lift whole   # always available for the function map
  case "$mode" in
    entry) key=whole; bc="$T/whole.bc"; defs="-DENTRYPOINT_SELECTOR=$arg $defs" ;;
    disp)  lift pi --function-pc "$(pc_of process_instruction)"; key=pi; bc="$T/pi.bc"
           [ "$arg" != "-" ] && defs="-DPROCESS_INSTRUCTION_SELECTOR=$arg $defs" ;;
    leaf)  lift "$arg" --function-pc "$(pc_of "$arg")"; key="$arg"; bc="$T/$arg.bc" ;;
  esac
  local out="$T/ko_$name"; rm -rf "$out"
  # syscall layer + CPI abstract-program models
  local objs=""
  for src in sbpf_runtime.c sbpf_sha256.c programs/cpi.c \
             programs/system_program.c programs/token_program.c; do
    local o="$T/$(basename "${src%.c}").bc"
    clang -I"$klee_inc" -I"$RT" $CF $defs "$RT/$src" -o "$o" 2>/dev/null
    objs="$objs $o"
  done
  rm -f "$T/h.bc"
  if ! clang -I"$klee_inc" -I"$RT" $CF $defs "$HD/$name.c" -o "$T/h.bc" 2>/dev/null; then
    echo "FAIL  $name [$mode $arg]: harness compile error"; fails=$((fails + 1)); return
  fi
  llvm-link "$bc" $objs "$T/h.bc" -o "$T/linked.bc" 2>/dev/null
  klee --output-dir="$out" --optimize=false "$T/linked.bc" >/dev/null 2>&1 || true
  local w; w=$(ls "$out" 2>/dev/null | grep -E '\.err$' | tr '\n' ' ')
  if echo "$w" | grep -qE 'ptr\.err|assert\.err'; then
    echo "FAIL  $name [$mode $arg]: ${w:-<no witness>}"; fails=$((fails + 1))
  else
    echo "ok    $name [$mode $arg]: ${w:-<no witness>}"
  fi
}

run_one entrypoint_lamport                entry 0
run_one entrypoint_lamport                entry 1 "-DEXPECT_SAFE_TRANSFER"
run_one vulnerable_transfer               disp  0
run_one safe_transfer                     disp  1
run_one vulnerable_token_transfer         disp  2
run_one safe_token2022_transfer_checked   disp  3
run_one system_transfer                   disp  -
run_one system_allocate                   disp  7
run_one clock_check                       disp  -
run_one clock_assert                      disp  -
run_one vulnerable_owner_ignored          leaf  withdraw_vulnerable
run_one safe_owner_gate                   leaf  withdraw_safe
run_one safe_owner_mismatch               leaf  withdraw_safe
run_one token_oracle_reject               leaf  transfer_token_vulnerable

echo "---"
[ "$fails" -eq 0 ] && echo "ALL HARNESSES OK" || { echo "$fails harness(es) FAILED"; exit 1; }
