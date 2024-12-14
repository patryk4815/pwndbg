from __future__ import annotations

import argparse
import contextlib
from typing import Literal
from typing import Tuple
from typing import TypedDict

import pwndbg.aglib.memory
import pwndbg.aglib.shellcode
import pwndbg.commands
import pwndbg.lib.abi
import pwndbg.lib.memory
import pwndbg.lib.regs
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""
    todo
""",
)
parser.add_argument(
    "fdnum",
    help="todo",
    type=int,
)
parser.add_argument(
    "newfile",
    help="todo",
    type=str,
)


class ShellcodeRegs(TypedDict):
    newfd: str
    syscall_ret: str
    stack: str


def get_shellcode_regs() -> ShellcodeRegs:
    register_set = pwndbg.lib.regs.reg_sets[pwndbg.aglib.arch.current]
    syscall_abi = pwndbg.lib.abi.ABI.syscall()

    # pickup free register what is not used for syscall abi
    newfd_reg = next(
        (
            reg_name
            for reg_name in register_set.gpr
            if reg_name not in syscall_abi.register_arguments
        )
    )
    assert (
        newfd_reg is not None
    ), f"architecture {pwndbg.aglib.arch.current} don't have unused register..."

    return {
        "newfd": newfd_reg,
        # FIXME: `retval` is syscall abi? or sysv abi?
        "syscall_ret": register_set.retval,
        "stack": register_set.stack,
    }


def stack_size_alignment(s: int) -> int:
    syscall_abi = pwndbg.lib.abi.ABI.syscall()
    return s + (syscall_abi.arg_alignment - (s % syscall_abi.arg_alignment))


def asm_replace_file(replace_fd: int, filename: str) -> Tuple[int, str]:
    filename = filename.encode() + b"\x00"

    from pwnlib import asm
    from pwnlib import constants
    from pwnlib import shellcraft

    regs = get_shellcode_regs()
    stack_size = stack_size_alignment(len(filename))

    open_asm = (
        shellcraft.syscall("SYS_open", regs["stack"], "O_CREAT|O_RDWR", 0o666)
        if hasattr(constants, "SYS_open")
        else shellcraft.syscall("SYS_openat", "AT_FDCWD", regs["stack"], "O_CREAT|O_RDWR", 0o666)
    )

    dup_asm = (
        shellcraft.syscall("SYS_dup2", regs["newfd"], replace_fd)
        if hasattr(constants, "SYS_dup2")
        else shellcraft.syscall("SYS_dup3", regs["newfd"], replace_fd, 0)
    )

    return stack_size, asm.asm(
        "".join(
            [
                shellcraft.pushstr(filename, False),
                open_asm,
                shellcraft.mov(regs["newfd"], regs["syscall_ret"]),
                dup_asm,
                shellcraft.syscall("SYS_close", regs["newfd"]),
            ]
        )
    )


def asm_replace_socket(
    replace_fd: int,
    host: str,
    port: int,
    proto: Literal["tcp", "udp"],
    network: Literal["ipv4", "ipv6"],
) -> Tuple[int, str]:
    # tcp+ipv4://127.0.0.1:8080
    # 127.0.0.1:8080

    from pwnlib import asm
    from pwnlib import constants
    from pwnlib import shellcraft
    from pwnlib.util.net import sockaddr

    sockdata, addr_len, address_family = sockaddr(host, port, network)
    socktype = {"tcp": "SOCK_STREAM", "udp": "SOCK_DGRAM"}[proto]

    regs = get_shellcode_regs()
    stack_size = stack_size_alignment(len(sockdata))

    dup_asm = (
        shellcraft.syscall("SYS_dup2", regs["newfd"], replace_fd)
        if hasattr(constants, "SYS_dup2")
        else shellcraft.syscall("SYS_dup3", regs["newfd"], replace_fd, 0)
    )

    return stack_size, asm.asm(
        "".join(
            [
                shellcraft.syscall("SYS_socket", address_family, socktype, 0),
                shellcraft.mov(regs["newfd"], regs["syscall_ret"]),
                shellcraft.pushstr(sockdata, False),
                shellcraft.syscall("SYS_connect", regs["newfd"], regs["stack"], addr_len),
                dup_asm,
                shellcraft.syscall("SYS_close", regs["newfd"]),
            ]
        )
    )


@contextlib.asynccontextmanager
async def exec_shellcode_with_stack(ec: pwndbg.dbg_mod.ExecutionController, blob, stack_size: int):
    stack_start = pwndbg.aglib.regs.sp
    original_stack = pwndbg.aglib.memory.read(stack_start - stack_size, stack_size)

    try:
        async with pwndbg.aglib.shellcode.exec_shellcode(
            ec, blob, restore_context=True, disable_breakpoints=True
        ):
            stack_end = pwndbg.aglib.regs.sp
            stack_diff_size = stack_start - stack_end

            # Make sure stack is not corrupted somehow
            assert not (
                stack_diff_size > stack_size
            ), f"stack is probably corrupted size_current=f{stack_diff_size} size_max_want={stack_size}"

            yield
    finally:
        pwndbg.aglib.memory.write(stack_start, original_stack)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MISC, command_name="hijack-fd")
@pwndbg.commands.OnlyWhenRunning
def hijack_fd(fdnum: int, newfile: str) -> None:
    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        s = asm_replace_file(fdnum, newfile)
        async with exec_shellcode_with_stack(ec, s[1], s[0]):
            print("x syscall returned")

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)


# class ParsedURL(NamedTuple):
#     protocol: str
#     ip_version: str
#     address: str
#     port: int
#
#
# def parse_url(url: str) -> Optional[ParsedURL]:
#     try:
#         # Parsowanie przy użyciu urlparse
#         parsed = urlparse(url)
#         if "+" not in parsed.scheme:
#             return None
#
#         protocol, ip_version = parsed.scheme.split("+", 1)
#
#         # Sprawdzanie hosta (IPv4 lub IPv6)
#         address = parsed.hostname
#         if not address:
#             return None
#
#         # Parsowanie portu
#         port = parsed.port
#         if not port:
#             return None
#
#         return ParsedURL(protocol, ip_version, address, port)
#     except ValueError:
#         return None
