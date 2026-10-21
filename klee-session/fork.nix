# Forked KLEE that also builds the resident `klee-session` query tool.
#
# Pinned to one explicit nixpkgs revision (nixos-24.11 era) that ships LLVM 16
# and KLEE 3.1. Reuses nixpkgs' KLEE build and adds, via postPatch: the tool
# sources, its tools/ registration, and one Executor method that exposes
# concrete reads of a kept state's per-object symbolic memory.
{ }:
let
  nixpkgs = builtins.getFlake
    "github:NixOS/nixpkgs/50ab793786d9de88ee30ec4e4c24fb4236fc2674";
  pkgs = import nixpkgs.outPath { };
  llvm = pkgs.llvmPackages_16;
  klee16 = pkgs.klee.override { llvmPackages = llvm; };
in
klee16.overrideAttrs (old: {
  pname = "klee-session";
  postPatch = (old.postPatch or "") + ''
    mkdir -p tools/klee-session
    cp ${./main.cpp} tools/klee-session/main.cpp
    cp ${./CMakeLists.txt} tools/klee-session/CMakeLists.txt
    echo 'add_subdirectory(klee-session)' >> tools/CMakeLists.txt
    bash ${./apply-executor-edits.sh}
  '';
})
