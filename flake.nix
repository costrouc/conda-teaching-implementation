{
  description = "Conda teaching implementation";

  inputs = {
    nixpkgs = { url = "github:nixos/nixpkgs/nixpkgs-unstable"; };
  };

  outputs = inputs@{ self, nixpkgs, ... }:
    (let
      pkgs = import nixpkgs { system = "x86_64-linux"; };
      pythonPackages = pkgs.python3Packages;
    in {
      devShell.x86_64-linux =
        pkgs.mkShell {
          buildInputs = [
            pythonPackages.pycco
          ];
        };
    });
}
