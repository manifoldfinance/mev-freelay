{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  packages = [
    pkgs.delve
    pkgs.gcc
    pkgs.gh
    pkgs.go-outline
    pkgs.go-tools
    pkgs.go_1_19
    pkgs.gocode
    pkgs.gocode-gomod
    pkgs.godef
    pkgs.golangci-lint
    pkgs.gopkgs
    pkgs.gopls
    pkgs.gotools
    pkgs.treefmt
  ];
  hardeningDisable = [ "all" ]; # to build the cross-compiler
  buildInputs = [
    # Install the latest version of Node.js and its associated packages
    pkgs.nodePackages_latest.prettier
  ];
}
