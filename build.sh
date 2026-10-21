#!/usr/bin/env bash
# Build the two native engine binaries: the Rust normalizer and the LLVM emitter.
# Run inside `nix develop` (or any shell with LLVM 16, KLEE, cmake, and cargo).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cargo build --release --manifest-path "$root/normalize/Cargo.toml"

cmake -S "$root/emitter" -B "$root/emitter/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "$root/emitter/build" -j"$(nproc)"

echo "normalizer: $root/normalize/target/release/sbpf-normalize"
echo "emitter:    $root/emitter/build/sbpf-llvm-emit"
