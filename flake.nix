{
  description = "Reverse proxy that puts a backend server behind a passkey login";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    forAllSystems = nixpkgs.lib.genAttrs [
      "x86_64-linux"
      "aarch64-linux"
      "aarch64-darwin"
    ];
  in {
    packages = forAllSystems (system: {
      default = nixpkgs.legacyPackages.${system}.callPackage ./nix/package.nix {};
    });

    # Provide the NixOS module's default package.
    overlays.default = final: _prev: {
      passkey-proxy = final.callPackage ./nix/package.nix {};
    };

    nixosModules.default = ./nix/module.nix;

    devShells = forAllSystems (system: {
      default = nixpkgs.legacyPackages.${system}.mkShell {
        packages = [
          # Match the package's Go toolchain.
          self.packages.${system}.default.passthru.go
          nixpkgs.legacyPackages.${system}.gopls
        ];
      };
    });
  };
}
