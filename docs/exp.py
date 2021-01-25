#!/usr/bin/env python2

from pwn import *
import sys
import argparse

def init_args():
    parser = argparse.ArgumentParser(prog='exp')
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('target', help="Binary path or remote host:port")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--debug', dest='debug', action='store_true')
    group.add_argument('--local', dest='local', action='store_true')
    group.add_argument('--remote', dest='remote', action='store_true')
    return parser.parse_args()

def setup_pipe(args, gdbrc):
    if args.debug:
        return gdb.debug(args.target, gdbrc)
    elif args.local:
        return process(args.target)
    elif args.remote:
        HOST, PORT = args.target.split(":", 1)
        return remote(HOST, PORT)

def setup_pwntools(args):
    if args.verbose:
        context.log_level = "debug"

    context.clear(
        arch="amd64",
        terminal=["tmux", "splitw", "-h"]
    )

if __name__ == "__main__":
    gdbrc = """
    b _start
    """

    args = init_args()
    setup_pwntools(args)
    io  = setup_pipe(args, gdbrc)
    if not args.remote:
        exe = ELF(args.target)
        rop = ROP(args.target)
    print(exe)
    # io.interactive()
