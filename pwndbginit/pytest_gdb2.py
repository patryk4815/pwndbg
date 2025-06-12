#!/usr/bin/env python3
import json
import signal
import time
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


class ForkedPlugin2:
    def pytest_runtest_protocol(self, item, nextitem):
        from _pytest.runner import runtestprotocol
        import marshal
        from os import environ

        try:
            reports = runtestprotocol(item, log=False)
        except KeyboardInterrupt:
            os._exit(4)

        fd_w = int(environ["_PWNDBG_TEST_PIPE_RESPONSE"])
        with os.fdopen(fd_w, "wb") as pipe_writer:
            pipe_writer.write(marshal.dumps([serialize_report(x) for x in reports]))
            pipe_writer.flush()

        os._exit(0)
        return True


def run_test_in_child():
    import sys
    sys._pwndbg_unittest_run = True
    from _pytest.config import _prepareconfig

    from os import environ
    item_nodeid = environ["_PWNDBG_TEST_PIPE_REQUEST"]
    argv = json.loads(environ["_PWNDBG_TEST_ARGS"])
    sys.argv = [sys.argv[0], *argv]

    config = _prepareconfig([item_nodeid, "-s", *sys.argv[1:]], plugins=[ForkedPlugin2()])
    ret = config.hook.pytest_cmdline_main(config=config)
    os._exit(ret)


def forked_run_report(item):
    import marshal
    from _pytest import runner
    from multiprocessing import Process

    gdb_path = shutil.which("pwndbg")

    r1, w1 = os.pipe()
    envs = os.environ.copy()
    envs["_PWNDBG_TEST_PIPE_REQUEST"] = item.nodeid
    envs["_PWNDBG_TEST_PIPE_RESPONSE"] = str(w1)
    envs["_PWNDBG_TEST_ARGS"] = json.dumps(sys.argv[1:])

    # print(item.config)  # _pytest.config.Config
    # print(item.config.args)
    # print(marshal.dumps(item.config))
    # print(item.config)
    # print(item.config)

    # TODO: --pdb?
    # todo: timeout
    proc = subprocess.run([
        gdb_path,
        "-nx",
        "-ex", f"py from pwndbginit.pytest_gdb import run_test_in_child; run_test_in_child()",
        "-ex", "quit",
    ], env=envs, text=True, pass_fds=(w1,), capture_output=True)
    os.close(w1)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr)
        # TODO: error

    # proc.returncode
    with os.fdopen(r1, "rb") as pipe_reader:
        result_data = pipe_reader.read()
    # os.close(r1)

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
        "-iex", "exit"
    ], env=envs)

if __name__ == "__main__":
    main()
