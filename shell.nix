{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    pkg-config
    bear
    gnumake
    gcc
    gdb
    libsodium
    clang
    cmake
    (python3.withPackages (ps: [ #goofy ass language🫏🫏🫏
      ps.pynacl
    ]))
    wireguard-tools
    iputils
  ];

shellHook = ''
    cat <<EOF > .clangd
      CompileFlags:
        Add:
        - "-isystem${pkgs.glibc.dev}/include"
        - "-isystem${pkgs.libsodium.dev}/include"
    EOF
    '';
}