#!/usr/bin/env python3
from typing import Tuple, List

import os
import sys
import shutil
import sysconfig
import subprocess

def get_gdb_version(path: str) -> Tuple[str, str]:
    result = subprocess.run(
        [
            path, "-nx", "--batch",
            "-iex", "py import sysconfig; print(sysconfig.get_config_var('INSTSONAME'), sysconfig.get_config_var('VERSION'))"
        ],
        capture_output=True,
        text=True
    )
    return tuple(result.stdout.strip().split(' ', 2))


def pytest_main(argv: List[str]) -> None:
    pass


def main():
    gdb_path = shutil.which("gdb")

    envs = os.environ.copy()
    envs['PYTHONNOUSERSITE'] = '1'
    envs['PYTHONPATH'] = ':'.join(sys.path)
    envs['PYTHONHOME'] = ':'.join([sys.prefix, sys.exec_prefix])

    expected = (sysconfig.get_config_var("INSTSONAME"), sysconfig.get_config_var("VERSION"))
    have = get_gdb_version(gdb_path)
    if have != expected:
        # TODO: nie zawsze to znaczy..
        print(f"ERROR: GDB is compiled for Python {have}, but your Python interpreter is version {expected}")
        sys.exit(1)

    # TODO: fajnie bylo by podac path do portable-release-pwndbg?
    args = sys.argv[1:]
    # print('ARGS:', args)
    orgarg = args
    if len(orgarg) >= 3 and orgarg[0] == '-s' and orgarg[1] == '-c':
        args = []
        if len(orgarg) >= 4 and orgarg[3] == '--multiprocessing-fork':
            args.extend(['-iex', 'py import sys; sys.argv.append("--multiprocessing-fork")'])
        args.extend(['-iex', 'py ' + orgarg[2]])
        args.extend(['-iex', 'quit'])
        # print('NEW ARGS:', args)

    os.execve(gdb_path, ["pwndbg"] + ["-q", "-nx", "-ix", "/Users/psondej/projekty/pwndbg/gdbinit.py"] + args, env=envs)

if __name__ == "__main__":
    main()
