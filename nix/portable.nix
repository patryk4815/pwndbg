{
  pkgs ? import <nixpkgs> { },
  pwndbg ? import ./pwndbg.nix { },
}:
let
  isLLDB = pwndbg.meta.isLLDB;
  lldb = pwndbg.meta.lldb;
  gdb = pwndbg.meta.gdb;
  python3 = pwndbg.meta.python3;
  pwndbgVenv = pwndbg.meta.pwndbgVenv;

  bundler = arg: (pkgs.callPackage ./bundle { } arg);

  ldName = pkgs.lib.readFile (
    pkgs.runCommand "bundle-ld-name-IFD" { nativeBuildInputs = [ pkgs.patchelf ]; } ''
      echo -n $(basename $(patchelf --print-interpreter "${gdb}/bin/gdb")) > $out
    ''
  );
  ldLoader = if pkgs.stdenv.isDarwin then "" else "\"$dir/lib/${ldName}\"";

  wrapperBinPwndbgGdbinit = pkgs.writeScript "pwndbg" ''
    #!/bin/sh
    dir="$(cd -- "$(dirname "$(dirname "$(realpath "$0")")")" >/dev/null 2>&1 ; pwd -P)"
    export PYTHONHOME="$dir"
    export PATH="$dir/bin/:$PATH"
    exec ${ldLoader} "$dir/exe/gdb" --quiet --early-init-eval-command="set auto-load safe-path /" --command=$dir/exe/gdbinit.py "$@"
  '';
  wrapperBinPy = file: pkgs.writeScript "pwndbg" ''
    #!/bin/sh
    dir="$(cd -- "$(dirname "$(dirname "$(realpath "$0")")")" >/dev/null 2>&1 ; pwd -P)"
    export PYTHONHOME="$dir"
    export PATH="$dir/bin/:$PATH"
    exec ${ldLoader} "$dir/exe/python3" "$dir/${file}" "$@"
  '';
  wrapperBin = file: pkgs.writeScript "pwndbg" ''
    #!/bin/sh
    dir="$(cd -- "$(dirname "$(dirname "$(realpath "$0")")")" >/dev/null 2>&1 ; pwd -P)"
    export PATH="$dir/bin/:$PATH"
    exec ${ldLoader} "$dir/${file}" "$@"
  '';

  pwndbgGdbBundled = bundler [
    "${gdb}/bin/gdb" "exe/gdb"
    "${gdb}/bin/gdbserver" "exe/gdbserver"
    "${gdb}/share/gdb/" "share/gdb/"
    "${pwndbgVenv}/lib/" "lib/"

    "${pwndbg.src}/pwndbg" "lib/${python3.libPrefix}/site-packages/"
    "${pwndbg.src}/gdbinit.py" "exe/gdbinit.py"

    "${wrapperBinPwndbgGdbinit}" "bin/pwndbg"
    "${wrapperBin "exe/gdbserver"}" "bin/gdbserver"
  ];

  pwndbgLldbBundled = bundler [
    "${lldb}/bin/.lldb-wrapped" "exe/lldb"
    "${lldb}/bin/lldb-server" "exe/lldb-server"
    "${lldb}/lib/" "lib/"
    "${pwndbgVenv}/lib/" "lib/"
    "${python3}/bin/python3" "exe/python3"

    "${pwndbg.src}/pwndbg" "lib/${python3.libPrefix}/site-packages/"
    "${pwndbg.src}/lldbinit.py" "exe/lldbinit.py"
    "${pwndbg.src}/pwndbg-lldb.py" "exe/pwndbg-lldb.py"

    "${wrapperBin "exe/lldb-server"}" "bin/lldb-server"
    "${wrapperBin "exe/lldb"}" "bin/lldb"
    "${wrapperBinPy "exe/pwndbg-lldb.py"}" "bin/pwndbg-lldb"
  ];
  pwndbgBundled = if isLLDB then pwndbgLldbBundled else pwndbgGdbBundled;

  portable =
    pkgs.runCommand "portable-${pwndbg.name}"
      {
        meta = {
          name = pwndbg.name;
          version = pwndbg.version;
          architecture = gdb.stdenv.targetPlatform.system;
        };
      }
      ''
        mkdir -p $out/pwndbg/
        # copy
        cp -rf ${pwndbgBundled}/* $out/pwndbg/

        # writable out
        chmod -R +w $out

        # skip venv
        touch $out/pwndbg/exe/.skip-venv

        # fix python "subprocess.py" to use "/bin/sh" and not the nix'ed version, otherwise "gdb-pt-dump" is broken
        substituteInPlace $out/pwndbg/lib/${python3.libPrefix}/subprocess.py --replace "'${pkgs.bash}/bin/sh'" "'/bin/sh'"

        # build pycache
        SOURCE_DATE_EPOCH=0 ${python3}/bin/python3 -c "import compileall; compileall.compile_dir('$out', stripdir='$out', force=True);"
      '';
in
portable
