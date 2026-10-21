{
  description = "sylana: symbolic execution of Solana sBPF programs";

  # Pinned to the one nixpkgs git revision that ships LLVM 16 + KLEE 3.1 (later
  # channels dropped llvmPackages_16). Same rev as shell.nix and
  # klee-session/fork.nix, so KLEE is a reproducible git dependency.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/50ab793786d9de88ee30ec4e4c24fb4236fc2674";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (s: f (import nixpkgs { system = s; }));
    in {
      devShells = forAll (pkgs:
        let
          llvm = pkgs.llvmPackages_16;
          klee16 = pkgs.klee.override { llvmPackages = llvm; };
        in {
          # Pinned LLVM 16, KLEE, and build tools. Rust is intentionally not
          # pinned: solana-sbpf 0.21.1 needs rustc >= 1.84 (newer than this
          # channel), so the normalizer uses the system toolchain on PATH.
          default = pkgs.mkShell {
            packages = [
              llvm.clang
              llvm.llvm
              klee16
              pkgs.cmake
              pkgs.git
              pkgs.python3
              pkgs.uv
            ];
            shellHook = "export SYLANA_SHELL=1";
          };
        });
    };
}
