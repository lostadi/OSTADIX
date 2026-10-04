{
  description = "Ostadix: Universal Lisp-Nix Shell Engine";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      # Supported build targets
      systems = [
        "aarch64-darwin"   # Apple Silicon macOS
        "x86_64-darwin"    # Intel macOS
        "x86_64-linux"     # x86 Linux (Arch, Ubuntu, NixOS)
        "aarch64-linux"    # ARM Linux
      ];

      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.rustPlatform.buildRustPackage {
            pname   = "ostadix";
            version = "0.1.0";
            src     = ./.;

            cargoLock.lockFile = ./Cargo.lock;

            # makeWrapper injects runtime tool paths into the compiled binary
            # so ostadix works regardless of what is installed on the host OS.
            nativeBuildInputs = [ pkgs.makeWrapper ];

            postInstall = ''
              wrapProgram $out/bin/ostadix \
                --prefix PATH : ${pkgs.lib.makeBinPath [
                  pkgs.sbcl
                  pkgs.nix
                  pkgs.coreutils
                  pkgs.rlwrap
                  pkgs.git
                ]}
            '';
          };
        }
      );

      # Expose as a Nix app so `nix run .` works
      apps = forAllSystems (system: {
        default = {
          type    = "app";
          program = "${self.packages.${system}.default}/bin/ostadix";
        };
      });
    };
}
