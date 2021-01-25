#!/usr/bin/env python2

from pwn import *
import sys

usage = """ One of [ REMOTE | BIN ] is required.
<REMOTE=1.2.3.4:80> [DEBUG]
<BIN=./ctfbin> [GDB,DEBUG]
"""

def init(gdbrc):
    if not args.REMOTE and not args.BIN:
        log.warn(usage)
        sys.exit(1)

    if args.REMOTE:
        HOST, PORT = args.REMOTE.split(":", 1)
        return remote(HOST, PORT)
    elif args.GDB:
        return gdb.debug(args.BIN, gdbrc)
    else:
        return process(args.BIN)

if __name__ == "__main__":
    gdbrc = """
    b _start
    """

    context.clear(
        arch="amd64",
        terminal=["tmux", "splitw", "-h"] # used if GDB is passed
    )

    io  = init(gdbrc)
    if not args.REMOTE:
        exe = ELF(args.BIN)
        rop = ROP(args.BIN)
    io.interactive()
