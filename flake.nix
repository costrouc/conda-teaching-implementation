{
  description = "Conda teaching implementation";

  inputs = {
    nixpkgs = { url = "github:nixos/nixpkgs/nixpkgs-unstable"; };
  };

  outputs = inputs@{ self, nixpkgs, ... }:
    (let
      pkgs = import nixpkgs { system = "x86_64-linux"; };
      pythonPackages = pkgs.python3Packages;

      pycco = pythonPackages.buildPythonPackage rec {
        name = "pycco";
        version = "0.6.0";

        src = pkgs.fetchFromGitHub {
          owner = "pycco-docs";
          repo = "pycco";
          rev = version;
          sha256 = "sha256-fo/yb4tAGbbVObnjGxfBYv/2eJ6OIPQCiLZITTMZpzo=";
        };

        propagatedBuildInputs = [
          pythonPackages.markdown
          pythonPackages.pygments
          pythonPackages.pystache
          pythonPackages.smartypants
        ];

        doCheck = false;
      };
    in {
      devShell.x86_64-linux.default =
        pkgs.mkShell {
          buildInputs = [
            pycco
          ];
        };

      packages.x86_64-linux.default =
        pkgs.runCommand "website" {
          src = ./.;
        } ''
          cd $src
          ls -la
          mkdir -p $out
          ${pycco}/bin/pycco conda.py -d $out
          mv $out/conda.html $out/index.html
        '';
    });
}
