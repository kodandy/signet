{
  description = "signet - Cryptographic authorization delegation layer for AI agents";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { nixpkgs, ... }:
  let
    systems = [ "aarch64-darwin" "x86_64-darwin" "x86_64-linux" "aarch64-linux" ];
    forAllSystems = nixpkgs.lib.genAttrs systems;
  in {
    devShells = forAllSystems (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in {
        default = pkgs.mkShell {
          packages = with pkgs; [
            git
            gh
            jq
            direnv
            bun
            typescript
          ];

          shellHook = ''
            echo "signet dev environment loaded (Bun $(bun --version))"
          '';
        };
      }
    );
  };
}
