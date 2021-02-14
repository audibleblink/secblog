#!/usr/bin/env python3

from pwn import *
import sys

usage = """
    sploit.py <BIN> [REMOTE=x.x.x.x:yy] [GDB,DEBUG]

    GDB     Enables use of GDB during exploit development. Require tmux.

    REMOTE= Set the host and port to which the exploit will be sent. 
            GDB cannot be used with this mode

    DEBUG   Enables debug logging in pwntool
"""

def init(gdbrc):
    if len(sys.argv) != 2:
        log.warn(usage)
        sys.exit(1)

    binary = sys.argv[1]
    context.binary = binary
    if args.REMOTE:
        HOST, PORT = args.REMOTE.split(":", 1)
        return remote(HOST, PORT)
    elif args.GDB:
        context.terminal=["tmux", "splitw", "-h", "-p", "75"]
        return gdb.debug(binary, gdbrc)
    else:
        return process(binary)


def main(io):
    exe = context.binary
    # good luck!
    io.interactive()

if __name__ == "__main__":
    gdbrc = """
    """
    io  = init(gdbrc)
    main(io)
