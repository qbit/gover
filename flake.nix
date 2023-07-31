{
  description = "gover: a tool for managing versions of Go";

  inputs.nixpkgs.url = "nixpkgs";

  outputs = {
    self,
    nixpkgs,
  }: let
    supportedSystems = ["x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin"];
    forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    nixpkgsFor = forAllSystems (system: import nixpkgs {inherit system;});
  in {
    overlay = _: prev: {inherit (self.packages.${prev.system}) gover;};

    packages = forAllSystems (system: let
      pkgs = nixpkgsFor.${system};
    in {
      gover = pkgs.buildGoModule {
        pname = "gover";
        version = "v0.0.0";
        src = ./.;

        vendorHash = "sha256-T1LtItKF1G161aoDG2EPOk47OOLhjtaWBAB1y+8r4sQ=";
      };
    });

    defaultPackage = forAllSystems (system: self.packages.${system}.gover);
    devShells = forAllSystems (system: let
      pkgs = nixpkgsFor.${system};
    in {
      default = pkgs.mkShell {
        shellHook = ''
          PS1='\u@\h:\@; '
          nix flake run github:qbit/xin#flake-warn
          echo "Go `${pkgs.go}/bin/go version`"
        '';
        nativeBuildInputs = with pkgs; [git go gopls go-tools];
      };
    });
  };
}
