#!/usr/bin/env python3

import sys
# from pwn import *
from pwn import (context, gdb, log, args, remote, process, ELF, cyclic)

usage = """
    sploit.py <BIN> [REMOTE=x.x.x.x:yy] [GDB,DEBUG]
    REMOTE= Set the host and port to which the exploit will be sent
            GDB cannot be used with this mode
    GDB     Enables use of GDB during exploit development. Requires tmux
    DEBUG   Enables debug logging in pwntools
"""

BIN = ""


def init(gdbrc):
    if len(sys.argv) != 2 and BIN == "":
        log.warn(usage)
        sys.exit(1)
    binary = BIN or sys.argv[1]
    context.binary = binary
    if args.REMOTE:
        HOST, PORT = args.REMOTE.split(":", 1)
        return remote(HOST, PORT)
    elif args.GDB:
        # context.terminal = ["tmux", "splitw", "-h", "-p", "75"]
        context.terminal = ["tmux", "neww"]
        return gdb.debug(binary, gdbrc)
    else:
        return process(binary)


def rebased_libc(leak, entry):
    if args.REMOTE == "":
        libc = context.binary.libc
    else:
        libc = ELF("./libc.so.6")
    libc.address = leak - libc.sym[entry]
    return libc


def main(io):
    # import ipdb;ipdb.set_trace(context=5)
    payload = cyclic(1024)
    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    gdbrc = """
    b main
    c
    """
    io = init(gdbrc)
    main(io)
