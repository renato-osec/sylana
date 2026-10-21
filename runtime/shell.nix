{ pkgs ? import (builtins.getFlake "nixpkgs").outPath { } }:

let
  llvm = pkgs.llvmPackages_16;
  klee16 = pkgs.klee.override { llvmPackages = llvm; };
in
pkgs.mkShell {
  packages = [
    llvm.clang
    llvm.llvm
    klee16
  ];

  shellHook = ''
    export OWNER_CHECK_KLEE_SHELL=1
  '';
}
