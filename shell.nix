let
  #pkgs = import (fetchTarball("https://github.com/NixOS/nixpkgs/archive/048958000f08aebb9ff0350a5b09d8f8a17c674e.tar.gz")) {};
  pkgs = import (fetchTarball("channel:nixpkgs-unstable")) {};
in pkgs.clangStdenv.mkDerivation {
  name = "libstatgrab-sys";
  buildInputs = [ pkgs.cargo pkgs.rustc pkgs.libstatgrab pkgs.libclang ];
  LIBCLANG_PATH = "${pkgs.llvmPackages_11.libclang.lib}/lib";
}
