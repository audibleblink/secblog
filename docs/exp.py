#!/usr/bin/env python2

from pwn import *
import sys

usage = """ Binary file required

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
        context.terminal=["tmux", "splitw", "-h"]
        return gdb.debug(binary, gdbrc)
    else:
        return process(binary)

if __name__ == "__main__":

    gdbrc = """
    b _start
    """

    io  = init(gdbrc)
    if not args.REMOTE:
        exe = ELF(context.binary.path)
        rop = ROP(exe)

    """
    Exploit code here
    """    

    io.interactive()
