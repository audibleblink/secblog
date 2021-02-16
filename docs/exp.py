#!/usr/bin/env python3

from pwn import *
import sys

usage = """ Usage: sploit.py <BIN> [REMOTE=x.x.x.x:yy] [GDB,DEBUG]

BIN         Required: binary file being exploited
GDB         Open GDB in a tmux pane
REMOTE=     The <host:port> to which the exploit will be sent. 
                * GDB cannot be used with this mode
DEBUG       Set the pwntools logger to 'debug'
"""

@context.quiet
def init(gdbrc):
    if len(sys.argv) != 2:
        log.critical(usage)
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
    # sys.stdout.buffer.write(payload)
    # import ipdb;ipdb.set_trace(context=5)

    io.sendline(cyclic(2048))
    io.recvline()


if __name__ == "__main__":
    gdbrc = """
    b main
    """
    io  = init(gdbrc)
    try:
        main(io)
    except EOFError as err:
        import ipdb;ipdb.set_trace(context=5)
        rip = io.corefile.fault_addr
        offset = cyclic_find(rip)
        log.critical("Pattern: %x\nOffset: %s", rip, offset)
