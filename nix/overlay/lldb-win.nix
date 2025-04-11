{
  prev,
  ...
}:
let
  lib = prev.lib;
  pkgsNative = prev.pkgsBuildHost;
  systemTarget = "x86_64-windows";

  llvmSrc = prev.pwndbg_lldb.passthru.monorepoSrc;

  tblgen = pkgsNative.callPackage ./tblgen.nix {
    release_version = builtins.elemAt (lib.strings.splitString "." prev.pwndbg_lldb.version) 0;
    version = prev.pwndbg_lldb.version;
    monorepoSrc = prev.pwndbg_lldb.passthru.monorepoSrc;
  };

  pythonWin = pkgsNative.stdenv.mkDerivation (
    finalAttrs:
    let
      verDate = "20250409";
      version = "3.12.10";
    in
    {
      passthru = {
        # Convert "3.12.9" -> "312"
        version_short = (
          let
            x1 = lib.strings.splitString "." version;
            x2 = (builtins.elemAt x1 0) + (builtins.elemAt x1 1);
          in
          x2
        );
      };
      name = "python3";
      version = version;
      src = pkgsNative.fetchurl {
        url = "https://github.com/astral-sh/python-build-standalone/releases/download/${verDate}/cpython-${version}%2B${verDate}-x86_64-pc-windows-msvc-install_only_stripped.tar.gz";
        sha256 = "sha256-CGcKto8EFIG4Ensuon4B3fVhMeYfz4RfSJAk/dzT3uw=";
      };
      dontStrip = true;
      dontConfigure = true;
      dontBuild = true;
      installPhase = ''
        mkdir $out
        mv * $out
      '';
    }
  );

  zigStdenv =
    pkgsNative.runCommand "zig-stdenv"
      {
        nativeBuildInputs = [ pkgsNative.makeWrapper ];
      }
      (
        let
          targetzig =
            {
              "x86_64-windows" = "x86_64-windows-gnu";
              "aarch64-windows" = "aarch64-windows-gnu";
            }
            .${systemTarget};
        in
        ''
          mkdir -p $out/bin/
          makeWrapper ${pkgsNative.zig}/bin/zig $out/bin/cc --add-flags "cc --target=${targetzig}"
          makeWrapper ${pkgsNative.zig}/bin/zig $out/bin/c++ --add-flags "c++ --target=${targetzig}"
          makeWrapper ${pkgsNative.zig}/bin/zig $out/bin/ar --add-flags "ar"
          makeWrapper ${pkgsNative.zig}/bin/zig $out/bin/ranlib --add-flags "ranlib"
        ''
      );

  env = pkgsNative.buildEnv {
    name = "env";
    paths = [
      pkgsNative.bash
      pkgsNative.coreutils
      pkgsNative.which
      pkgsNative.gnumake
      pkgsNative.cmake
      pkgsNative.ninja
      pkgsNative.swig
      zigStdenv
    ];
  };

  drv = pkgsNative.runCommand "lldb-win" { } (
    let
      cmakeFlags = [
        "-G Ninja"
        "-DLLVM_TABLEGEN=${tblgen}/bin/llvm-tblgen"
        "-DCLANG_TABLEGEN=${tblgen}/bin/clang-tblgen"
        "-DLLDB_TABLEGEN_EXE=${tblgen}/bin/lldb-tblgen"
        "-DCMAKE_BUILD_TYPE=Release"
        "-DLLVM_ENABLE_PROJECTS=\"clang;lldb\""
        "-DLLVM_EXPERIMENTAL_TARGETS_TO_BUILD=\"Xtensa;M68k\""
        "-DLLDB_INCLUDE_TESTS=OFF"

        "-DLLDB_ENABLE_LUA=OFF"
        "-DLLVM_ENABLE_LTO=ON" # # Run OFF for local testing. Faster compilation with OFF.
        "-DLLDB_ENABLE_SWIG=ON"
        "-DLLDB_ENABLE_PYTHON=ON"

        "-DLLDB_PYTHON_RELATIVE_PATH=\"Lib/site-packages\""
        "-DLLDB_PYTHON_EXE_RELATIVE_PATH=\"Scripts/python.exe\""
        "-DLLDB_PYTHON_EXT_SUFFIX=${
          {
            "x86_64-windows" = ".cp${pythonWin.passthru.version_short}-win_amd64.pyd";
            "aarch64-windows" = ".cp${pythonWin.passthru.version_short}-win_arm64.pyd";
          }
          .${systemTarget}
        }"

        "-DLLDB_EMBED_PYTHON_HOME=ON"
        "-DLLDB_PYTHON_HOME=."
        "-DPython3_LIBRARIES=${pythonWin}/python${pythonWin.passthru.version_short}.dll"
        "-DPython3_INCLUDE_DIRS=${pythonWin}/include"
        "-DPython3_RPATH=${pythonWin}/libs"
        "-DPython3_EXECUTABLE=${pkgsNative.python3}/bin/python3"

        "-DCMAKE_SYSTEM_NAME=Windows"
        "-DCMAKE_SYSTEM_PROCESSOR=${
          {
            "x86_64-windows" = "x86_64";
            "aarch64-windows" = "Aarch64";
          }
          .${systemTarget}
        }"
        "-DLLVM_HOST_TRIPLE=${
          {
            "x86_64-windows" = "x86_64-unknown-windows-gnu";
            "aarch64-windows" = "aarch64-unknown-windows-gnu";
          }
          .${systemTarget}
        }"
      ];
    in
    ''
      set -ex
      export PATH=${env}/bin/
      export HOME=$(mktemp -d)
      export TMPDIR=$(mktemp -d)

      cmake ${llvmSrc}/llvm ${lib.concatStringsSep " " cmakeFlags}

      ninja -v lldb lldb-server

      mkdir $out
      mv bin $out/
      mv Lib $out/ || true
    ''
  );
in
drv
