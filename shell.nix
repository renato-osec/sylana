# Build/dev environment for sylana, pinned to one explicit nixpkgs revision so
# it reproduces on any machine (LLVM 16 and KLEE 3.1 only exist in this era of
# nixpkgs). solders/solana are not pinned here; tests fetch them with `uv run
# --with solders`. The local `sylana` package is put on PYTHONPATH. Rust is the
# system toolchain (solana-sbpf 0.21.1 needs rustc >= 1.84).
{ }:
let
  nixpkgs = builtins.getFlake
    "github:NixOS/nixpkgs/50ab793786d9de88ee30ec4e4c24fb4236fc2674";
  pkgs = import nixpkgs.outPath { };
  llvm = pkgs.llvmPackages_16;
  klee16 = pkgs.klee.override { llvmPackages = llvm; };
in
pkgs.mkShell {
  packages = [
    llvm.clang
    llvm.llvm
    klee16
    pkgs.cmake
    pkgs.git
    pkgs.python3
    pkgs.uv
  ];

  shellHook = ''
    export SYLANA_SHELL=1
    export PYTHONPATH="${toString ./.}/python''${PYTHONPATH:+:$PYTHONPATH}"
  '';
}
