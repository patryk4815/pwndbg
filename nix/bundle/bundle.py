import subprocess
import shutil
import os
import os.path
import typing
import sys
from pathlib import Path


def check_file_type(file_path: Path) -> str | None:
    with open(str(file_path), 'rb') as f:
        header = f.read(4)

    if header == b'\x7fELF':
        return "ELF"
    elif header == b'\xfe\xed\xfa\xce':
        return "Mach-O 32-bit (Little Endian)"
    elif header == b'\xfe\xed\xfa\xcf':
        return "Mach-O 64-bit (Little Endian)"
    elif header == b'\xce\xfa\xed\xfe':
        return "Mach-O 32-bit (Big Endian)"
    elif header == b'\xcf\xfa\xed\xfe':
        return "Mach-O 64-bit (Big Endian)"
    elif header == b'\xca\xfe\xba\xbe':
        return "Mach-O Fat Binary (Universal, Little Endian)"
    elif header == b'\xbe\xba\xfe\xca':
        return "Mach-O Fat Binary (Universal, Big Endian)"
    else:
        return None


def eprint(msg: str):
    print(msg, file=sys.stderr)


def run(args: typing.List[str], no_error=False) -> str:
    result = subprocess.run(args, capture_output=True)
    if result.returncode != 0:
        if no_error:
            eprint(result.stderr)
            eprint("WARNING: Command failed with return code {}: {}".format(result.returncode, args))
            return ''

        eprint(result.stderr)
        eprint("Command failed with return code {}: {}".format(result.returncode, args))
        sys.exit(result.returncode)
    return result.stdout.decode("utf-8")


def iter_macho_deps(binary_path: Path) -> typing.Iterator[Path]:
    for line in run(["otool", "-L", str(binary_path)]).splitlines():
        line = line.strip()
        if not line.startswith('/nix/store/'):
            continue

        splited = line.split(' (', 1)
        if len(splited) != 2:
            continue

        lib_path = Path(splited[0])
        if not lib_path.exists():
            eprint(f'WARNING: skipping not exists file={lib_path}')
            continue

        yield lib_path


def iter_elf_deps(binary_path: Path) -> typing.Iterator[Path]:
    def stripped_strs(strs: typing.Iterable[str]) -> typing.Iterable[str]:
        return (cleaned for x in strs for cleaned in [x.strip()] if cleaned != "")

    def get_rpaths(exe: str) -> typing.Iterable[str]:
        return stripped_strs(run(["patchelf", "--print-rpath", exe]).split(":"))

    def resolve_origin(origin: str, paths: typing.Iterable[str]) -> typing.Iterable[str]:
        return (path.replace("$ORIGIN", origin) for path in paths)

    def get_needed(exe: str) -> typing.Iterable[str]:
        return stripped_strs(run(["patchelf", "--print-needed", exe]).splitlines())

    def resolve_paths(needed: typing.Iterable[str], rpaths: typing.List[str]) -> typing.Iterable[str]:
        existing_paths = lambda lib, paths: (
            abs_path for path in paths for abs_path in [os.path.join(path, lib)]
            if os.path.exists(abs_path)
        )
        for lib in needed:
            for found in [next(existing_paths(lib, rpaths), None)]:
                if found is None:
                    eprint(f"WARNING: can't find {lib} in {rpaths}")
                    continue

                yield found

    dirname = os.path.dirname(str(binary_path))
    rpaths_raw = list(get_rpaths(str(binary_path)))
    rpaths_raw = [dirname] if rpaths_raw == [] else rpaths_raw
    rpaths = list(resolve_origin(dirname, rpaths_raw))
    for path in (x for x in resolve_paths(get_needed(str(binary_path)), rpaths) if x is not None):
        if not path.startswith('/nix/store/'):
            continue
        yield Path(path)


if sys.platform == 'darwin':
    iter_deps = iter_macho_deps
else:
    iter_deps = iter_elf_deps


def iter_deps_recursive(binary_path: Path, depth: int=None, visited: typing.Set[Path]=None)  -> typing.Iterator[Path]:
    is_first = depth is None
    if depth is None:
        depth = 0
    if visited is None:
        visited = set()

    if depth > 20:
        raise ValueError(f'depth exceeded {depth}')

    binary_path = Path(os.path.normpath(binary_path))
    if binary_path in visited:
        return

    visited.add(binary_path)
    if not is_first:
        yield binary_path

    for dep in iter_deps(binary_path):
        yield from iter_deps_recursive(dep, depth=depth + 1, visited=visited)


def iter_dir_recursive(dir_path: Path, depth: int = None, visited: typing.Set[Path] = None) -> typing.Iterator[
    typing.Tuple[Path, typing.List[Path]]]:
    if depth is None:
        depth = 0
    if visited is None:
        visited = set()

    if depth > 20:
        raise ValueError(f'depth exceeded {depth}')

    if dir_path in visited:
        return

    visited.add(dir_path)

    stored_dirs = []
    stored_files = []

    for entry in dir_path.iterdir():
        if entry.is_dir():
            stored_dirs.append(entry)
        elif entry.is_file():
            stored_files.append(entry)
        else:
            raise ValueError('Unrecognized entry: {}'.format(entry))

    yield dir_path, stored_files
    del stored_files

    for subdir in stored_dirs:
        yield from iter_dir_recursive(subdir, depth=depth + 1, visited=visited)


def cleanup_nixrefs(binary_path: Path):
    # Modify the binary to replace references to actual Nix store paths (e.g., /nix/store/valid-hash)
    # with invalid or placeholder paths (e.g., /nix/store/invalid-hash), ensuring the binary
    # doesn’t inadvertently depend on specific Nix store contents.
    run(['nuke-refs', str(binary_path)])

    if sys.platform == 'darwin':
        # Force an "ad-hoc" code signature on the binary (using '-' as the identity placeholder).
        # This is typically used to satisfy macOS code signing requirements without a valid signing certificate.
        # The `-f` option forces re-signing if the binary is already signed.
        run(['codesign', '-f', '-s', '-', str(binary_path)], no_error=True)


def patch_library_macho(binary_path: Path, root_dst: Path, *, is_exe: bool):
    lib_dir = root_dst / 'lib'
    if is_exe:
        # For executable files (e.g., /abs/exe/gdb), replace absolute library paths with paths relative to the executable.
        # Example: replace /abs/lib/libLLVM.dylib with @executable_path/../lib/libLLVM.dylib
        # This makes the executable locate libraries in its own relative directory structure at runtime.
        prefix_lib = '@executable_path/'
    else:
        # For shared libraries (e.g., /abs/lib/python3.12/capstone/foo.dylib), replace absolute library paths with paths relative to the library.
        # Example: replace /abs/lib/libiconv.2.dylib with @loader_path/../../libiconv.2.dylib
        # This allows libraries to locate dependencies in a relative directory structure without absolute paths.
        prefix_lib = '@loader_path/'

    # When `binary_path` is already patched. `iter_deps` should return empty list
    for src_lib_path in iter_deps(binary_path):
        dst_lib_path = lib_dir / src_lib_path.name

        rel_path = os.path.relpath(dst_lib_path, binary_path.parent)
        print(f'Patching {binary_path.name}: {src_lib_path.name}->{rel_path}')
        run(["install_name_tool", "-change", str(src_lib_path), prefix_lib + rel_path, str(binary_path)])

    cleanup_nixrefs(binary_path)

def patch_library_elf(binary_path: Path, root_dst: Path, *, is_exe: bool):
    prefix_lib = '$ORIGIN/../lib'
    print(f'Patching {binary_path.name}')

    # When `binary_path` is already patched. `iter_deps` should return empty list
    # We need to be sure to not patch ld-loader or libc
    is_rpath_patch_needed = bool(next(iter_deps(binary_path), None))

    if is_rpath_patch_needed:
        if is_exe:
            interpreter_path = Path(run(["patchelf", "--print-interpreter", str(binary_path)]).strip())
            run(["patchelf", "--set-interpreter", interpreter_path.name, "--set-rpath", prefix_lib, str(binary_path)])
        else:
            run(["patchelf", "--set-rpath", prefix_lib, str(binary_path)])

    cleanup_nixrefs(binary_path)


if sys.platform == 'darwin':
    patch_library = patch_library_macho
else:
    patch_library = patch_library_elf


def copy_with_symlink2(src_file_path: Path, root_dir_src: Path, root_dst_dir: Path) -> Path | None:
    dst_file_path = root_dst_dir / src_file_path.relative_to(root_dir_src)
    if dst_file_path.exists():
        return dst_file_path

    if src_file_path.is_symlink():
        file_resolved = src_file_path.resolve()
        if file_resolved.is_relative_to(root_dir_src):
            # symlinked-file.txt should points to relative ../../original-file.txt
            # Allowed to create symlink, because they are under same root

            rel_path = os.path.relpath(file_resolved, src_file_path.parent)
            print(f'CopyingSym {dst_file_path}->{rel_path}')
            dst_file_path.symlink_to(rel_path)

            new_real_dst = root_dst_dir / file_resolved.relative_to(root_dir_src)
            if new_real_dst.exists():
                return new_real_dst

            print(f'Copying {src_file_path.name} to {new_real_dst.parent}')
            shutil.copy(src_file_path, new_real_dst, follow_symlinks=True)

            return new_real_dst
        else:
            # hard copy file without symlink, because they are in different root
            pass

    print(f'Copying {src_file_path.name} to {dst_file_path.parent}')
    shutil.copy(src_file_path, dst_file_path, follow_symlinks=True)
    return dst_file_path


def copy_with_symlink(src_path: Path, dst_dir: Path) -> Path | None:
    new_file = dst_dir / src_path.name
    if new_file.exists():
        return new_file

    if src_path.is_symlink():
        src_resolved_lib_path = src_path.resolve()
        is_weird_symlink = src_resolved_lib_path.name == src_path.name
        if is_weird_symlink:
            eprint(f'WARNING: Shouldn\'t happen? {src_path}->{src_resolved_lib_path}, coping file')

            print(f'Bundling {src_path.name} to {new_file.parent}')
            shutil.copy(src_path, new_file, follow_symlinks=True)
            return new_file

        symlink_path = dst_dir / src_path.name
        print(f'BundlingSym {symlink_path.name}->{src_resolved_lib_path.name} to {symlink_path.parent}')
        symlink_path.symlink_to(src_resolved_lib_path.name)

        new_file = dst_dir / src_resolved_lib_path.name
        if new_file.exists():
            return new_file

        print(f'Bundling {src_resolved_lib_path.name} to {new_file.parent}')
        shutil.copy(src_resolved_lib_path, new_file, follow_symlinks=True)
        return new_file
    else:
        print(f'Bundling {src_path.name} to {new_file.parent}')
        shutil.copy(src_path, new_file, follow_symlinks=True)
        return new_file


def bundle_library(binary_path: Path, root_dst: Path, *, is_exe: bool, dst_path: Path=None):
    lib_dir = root_dst / 'lib'
    exe_dir = root_dst / 'exe'
    exe_dir.mkdir(parents=True, exist_ok=True)
    lib_dir.mkdir(parents=True, exist_ok=True)

    if not binary_path.is_relative_to(root_dst):
        # coping required, because src-binary and dst-binary are in different roots
        binary_path = copy_with_symlink(binary_path, exe_dir if is_exe else lib_dir)

        # Move file to another place
        if is_exe and dst_path:
            shutil.move(binary_path, dst_path)
            binary_path = dst_path

    # Store all needed libs into {root}/lib/*
    for src_lib_path in iter_deps_recursive(binary_path):
        real_file = copy_with_symlink(src_lib_path, lib_dir)
        if real_file is None:
            continue
        patch_library(real_file, root_dst, is_exe=False)

    # fix main
    patch_library(binary_path, root_dst, is_exe=is_exe)


def bundle_python_venv(src_lib_dir: Path, out_lib_dir: Path, root_dst: Path):
    bundle_binaries = set()
    for src_dir_path, files in iter_dir_recursive(src_lib_dir):
        dst_dir_path = out_lib_dir / src_dir_path.relative_to(src_lib_dir)
        dst_dir_path.mkdir(parents=True, exist_ok=True)

        for src_file_path in files:
            # search for so files:
            # - /libpython3.12.so.1.0
            # - /libpython3.12.so
            # - /libpython3.12.dylib
            is_so = any(suffix in src_file_path.suffixes for suffix in (
                '.so',
                '.dylib',
            ))

            is_good_ext = src_file_path.suffix in (
                '.py',  # python script file
                '.pyi', '.typed',  # python types
                '.asm',  # pwntools asm templates
            )
            is_good_name = src_file_path.name in (
                '__doc__',  # pwntools asm templates
            )

            if not (is_so or is_good_ext or is_good_name):
                continue

            real_file = copy_with_symlink2(src_file_path, src_lib_dir, out_lib_dir)
            if is_so and real_file:
                bundle_binaries.add(real_file)

    for file in bundle_binaries:
        bundle_library(file, root_dst, is_exe=False)


def main():
    out = Path(sys.argv[1])
    rest_argv = sys.argv[2:]

    for src_path, dst_part in zip(rest_argv[::2], rest_argv[1::2]):
        is_dir = str(dst_part).endswith('/')
        src_path = Path(src_path)
        dst_part = Path(dst_part)
        dst_path = out / dst_part

        if is_dir:
            bundle_python_venv(src_path, dst_path, out)
        else:
            if check_file_type(src_path):
                bundle_library(src_path, out, is_exe=True, dst_path=dst_path)
            else:
                dst_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(src_path, dst_path, follow_symlinks=True)


main()
