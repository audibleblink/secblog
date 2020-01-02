#!/usr/bin/env python

from pwn import *
import sys

BIN = ""

def setup_pipe(gdb_commands):
    if len(sys.argv) < 2:
        error("Run mode missing: [debug, local, remote <server> <port>]")

    context.clear(
        arch="amd64",
        terminal=["tmux", "splitw"]
    )

    if "-v" in sys.argv:
        context.log_level = "debug"

    opt = sys.argv[1]
    if opt == "debug":
        return gdb.debug(BIN, gdb_commands)
    elif opt == "remote" and len(sys.argv) >= 4:
        HOST, PORT = sys.argv[2], sys.argv[3]
        return remote(HOST, PORT)
    elif opt == "local":
        return process(BIN)
    else:
        error("Run mode missing: [debug, local, remote <server> <port>]")


if __name__ == "__main__":
    gdbrc = """
    """

    exe, rop = ELF(BIN), ROP(BIN)
    io  = setup_pipe(gdbrc)

    io.interactive()
