from __future__ import annotations

import os
import random
import string
import subprocess
import tempfile
from typing import List
from typing import Tuple

from pt.machine import Machine

import pwndbg
import pwndbg.lib.cache
import pwndbg.lib.memory
import pwndbg.color.message as M

if pwndbg.dbg.is_gdblib_available():
    # The code in pwndbg.gdblib.vmmap does _so much_ more than just getting the
    # entries of the vmmap. We'll probably have to port it to run on top of the
    # Debugger-agnostic API, rather than embed its functionality inside it. When
    # that happens, this file will become that port. For now, we just fall back
    # on gdblib if possible, and expose weaker versions of these functions when
    # it's not available.
    #
    # TODO: Port `pwndbg.gdblib.vmmap` to `aglib`.
    import pwndbg.gdblib.vmmap


@pwndbg.lib.cache.cache_until("start", "stop")
def get() -> Tuple[pwndbg.lib.memory.Page, ...]:
    return tuple(pwndbg.dbg.selected_inferior().vmmap().ranges())


@pwndbg.lib.cache.cache_until("start", "stop")
def find(address: int | pwndbg.dbg_mod.Value | None) -> pwndbg.lib.memory.Page | None:
    if address is None:
        return None

    address = int(address)

    for page in get():
        if address in page:
            return page

    if pwndbg.dbg.is_gdblib_available():
        return pwndbg.gdblib.vmmap.explore(address)
    return None


class QemuMachine(Machine):
    def __init__(self):
        super().__init__()
        self.pid = QemuMachine.get_qemu_pid()
        self.file = os.open(f"/proc/{self.pid}/mem", os.O_RDONLY)
        self.mem_size = os.fstat(self.file).st_size

    def __del__(self):
        if self.file:
            os.close(self.file)

    def read_physical_memory(self, physical_address: int, length: int) -> bytes:
        res = pwndbg.dbg.selected_inferior().send_monitor(f"gpa2hva {hex(physical_address)}")

        # It's not possible to pread large sizes, so let's break the request
        # into a few smaller ones.
        max_block_size = 1024 * 1024 * 256
        try:
            hva = int(res.split(" ")[-1], 16)
            data = b""
            for offset in range(0, length, max_block_size):
                length_to_read = min(length - offset, max_block_size)
                block = os.pread(self.file, length_to_read, hva + offset)
                data += block
            return data
        except Exception as e:
            msg = f"Physical address ({hex(physical_address)}, +{hex(length)}) is not accessible. Reason: {e}. gpa2hva result: {res}"
            raise OSError(msg)

    @staticmethod
    def search_pids_for_file(pids: List[str], filename: str) -> str | None:
        for pid in pids:
            fd_dir = f"/proc/{pid}/fd"
            try:
                for fd in os.listdir(fd_dir):
                    if os.readlink(f"{fd_dir}/{fd}") == filename:
                        return pid
            except FileNotFoundError:
                # Either the process has gone or fds are changing, not our pid
                pass
            except PermissionError:
                # Evade processes owned by other users
                pass

        return None

    @staticmethod
    def get_qemu_pid():
        # fixme: remove pgrep?
        out = subprocess.check_output(["pgrep", "qemu-system"], encoding="utf8")
        pids = out.strip().split("\n")

        if len(pids) == 1:
            return int(pids[0], 10)

        # We add a chardev file backend (we dont add a fronted, so it doesn't affect
        # the guest). We can then look through proc to find which process has the file
        # open. This approach is agnostic to namespaces (pid, network and mount).
        chardev_id = "gdb-pt-dump" + "-" + "".join(random.choices(string.ascii_letters, k=16))
        with tempfile.NamedTemporaryFile() as tmpf:
            pwndbg.dbg.selected_inferior().send_monitor(
                f"chardev-add file,id={chardev_id},path={tmpf.name}"
            )
            pid_found = QemuMachine.search_pids_for_file(pids, tmpf.name)
            pwndbg.dbg.selected_inferior().send_monitor(f"chardev-remove {chardev_id}")

        if not pid_found:
            raise Exception("Could not find qemu pid")

        return int(pid_found, 10)

    def read_register(self, register_name: str) -> int:
        if register_name.startswith("$"):
            register_name = register_name[1:]

        return int(getattr(pwndbg.aglib.regs, register_name))


@pwndbg.lib.cache.cache_until("stop")
def kernel_vmmap_via_page_tables() -> Tuple[pwndbg.lib.memory.Page, ...]:
    from pt.pt import PageTableDump
    from pt.pt_aarch64_parse import PT_Aarch64_Backend
    from pt.pt_riscv64_parse import PT_RiscV64_Backend
    from pt.pt_x86_64_parse import PT_x86_64_Backend

    # If paging is not enabled, we shouldn't attempt to parse page tables
    if not pwndbg.aglib.kernel.paging_enabled():
        return ()

    try:
        machine_backend = QemuMachine()
    except PermissionError:
        print(
            M.error(
                "Permission error when attempting to parse page tables with gdb-pt-dump.\n"
                "Either change the kernel-vmmap setting, re-run GDB as root, or disable "
                "`ptrace_scope` (`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`)"
            )
        )
        return ()

    arch = pwndbg.aglib.arch.current
    if arch == "aarch64":
        arch_backend = PT_Aarch64_Backend(machine_backend)
    elif arch == "x86-64" in arch:
        # TODO: i386?
        arch_backend = PT_x86_64_Backend(machine_backend)
    elif arch == "rv64":
        arch_backend = PT_RiscV64_Backend(machine_backend)
    else:
        raise Exception(f"Unknown arch. Message: {arch}")

    p = PageTableDump(machine_backend, arch_backend)
    pages = p.arch_backend.parse_tables(p.cache, p.parser.parse_args(""))

    retpages: List[pwndbg.lib.memory.Page] = []
    for page in pages:
        start = page.va
        size = page.page_size
        flags = 4  # IMPLY ALWAYS READ
        if page.pwndbg_is_writeable():
            flags |= 2
        if page.pwndbg_is_executable():
            flags |= 1
        objfile = f"[pt_{hex(start)[2:-3]}]"
        retpages.append(pwndbg.lib.memory.Page(start, size, flags, 0, objfile))

    return tuple(retpages)
