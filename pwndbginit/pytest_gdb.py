#!/usr/bin/env python3
import json
import multiprocessing
import signal
import time
import typing
from typing import Tuple, List

import os
import sys
import shutil
import subprocess
import pytest


def serialize_report(rep):
    import py

    d = rep.__dict__.copy()
    if hasattr(rep.longrepr, "toterminal"):
        d["longrepr"] = str(rep.longrepr)
    else:
        d["longrepr"] = rep.longrepr
    for name in d:
        if isinstance(d[name], py.path.local):
            d[name] = str(d[name])
        elif name == "result":
            d[name] = None  # for now
    return d


class ForkedPlugin:
    def pytest_runtest_protocol(self, item, nextitem):
        ihook = item.ihook
        ihook.pytest_runtest_logstart(nodeid=item.nodeid, location=item.location)
        reports = forked_run_report(item)
        for rep in reports:
            ihook.pytest_runtest_logreport(report=rep)
        ihook.pytest_runtest_logfinish(nodeid=item.nodeid, location=item.location)
        return True


from multiprocessing.connection import Connection
class ForkedPlugin2:
    def __init__(self, q):
        self.conn: Connection = q

    def pytest_runtest_protocol(self, item, nextitem):
        from _pytest.runner import runtestprotocol
        import marshal

        try:
            reports = runtestprotocol(item, log=False)
        except KeyboardInterrupt:
            print('EXIT555 - KeyboardInterrupt')
            self.conn.send_bytes(b"KeyboardInterrupt")
            self.conn.close()
            os._exit(4)
        except Exception as e:
            print('EXI6666 - ' + str(e))
            self.conn.send_bytes(b"Error")
            self.conn.close()
            os._exit(4)

        self.conn.send_bytes(marshal.dumps([serialize_report(x) for x in reports]))
        self.conn.close()
        return True


def run_test_in_child(argv: List[str], item_nodeid: str, q):
    import sys
    sys._pwndbg_unittest_run = True
    from _pytest.config import _prepareconfig

    # devnull = os.open(os.devnull, os.O_WRONLY)
    # os.dup2(devnull, 1)  # stdout
    # os.dup2(devnull, 2)  # stderr

    # TODO --pdb disable jak nie ma tty - sys.stdin.isatty()
    # print("Running test in child process")
    # print(sys.stdin.isatty())
    # print(sys.stdin.isatty())
    # print(sys.stdin.isatty())
    argv_old = argv.copy()
    argv = []
    for value in argv_old:
        if value.startswith("--cov"):
            continue
        if value == "-s":
            continue
        argv.append(value)

    config = _prepareconfig([item_nodeid, "-s", *argv[2:]], plugins=[ForkedPlugin2(q)])
    config.hook.pytest_cmdline_main(config=config)
    # os._exit(1)


def forked_run_report(item):
    import marshal
    from _pytest import runner
    import multiprocessing

    gdb_path = shutil.which("pwndbg")

    # TODO: --pdb?
    # TODO: --cov?
    # todo: timeout
    ctx = multiprocessing.get_context('spawn')
    ctx.set_executable(gdb_path)
    parent_conn, child_conn = ctx.Pipe()  # type: Connection
    p = ctx.Process(target=run_test_in_child, args=(sys.argv, item.nodeid, child_conn))
    p.start()
    result_data = parent_conn.recv_bytes()
    p.join()
    # p.close()

    report_dumps = marshal.loads(result_data)
    return [runner.TestReport(**x) for x in report_dumps]


def pytest_main(argv: List[str]) -> None:
    sys.argv = [sys.argv[0], *argv]
    retcode = pytest.main(argv, plugins=[ForkedPlugin()])
    os._exit(retcode)


def main():
    gdb_path = shutil.which("pwndbg")

    envs = os.environ.copy()
    envs['PWNDBG_DISABLE_COLORS'] = '1'

    # TODO: fajnie bylo by podac path do portable-release-pwndbg?
    args = sys.argv[1:]
    os.execve(gdb_path, ["pytest-gdb"] + [
        "-nx",
        "-iex", f"py import pwndbginit.pytest_gdb; pwndbginit.pytest_gdb.pytest_main({args})"
        "-iex", "quit"
    ], env=envs)

if __name__ == "__main__":
    main()
