---
title: "Pwntool Tips 2"
date: 2020-01-03T13:13:01-05:00
toc: true
images:
tags:
  - pwntools
  - exploitdev
---

# ELF and ROP Modules
Pwntools gives us the ability to interact with ELFs and shared libraries in a programmatic way.

* Full [ELF docs](http://docs.pwntools.com/en/stable/elf/elf.html)
* Full [ROP docs](http://docs.pwntools.com/en/stable/rop/rop.html)

## ELF


### fit
One of the Class-level members I want to talk about is `fit`. I've had to create lines in my
exploit code that look like this:

```python
buf_len = 128
pad_len = buf_len - (len(gadgets) + len(mprotect))

payload  = gadgets
payload += mprotect
payload += "A" * pad_len
payload += canary
payload += "A" * 16 # junk
payload += jmprsp
```

`fit` allows you to be declarative about where each of your exploit components should be in your
payload. 

The same payload, using `fit`:
```python
payload = fit({
        0: gadgets,
        8: mprotect,
        128: canary,
        144: jmprsp
    })
```

All padding between the declared sections is inserted for you. Bonus, it uses the same pattern
that `cyclic` uses, so if your binary crashes during the exploit, the resulting address in the
crash screen of GDB can be inserted into `cyclic_find` and it will tell you where the cause of the
crash is in your payload. Much like using `pattern_create` to find an initial buffer length. I'll
go into `cyclic` in another blog post.

```python
In [1]: from pwn import *
In [2]: exp = fit({
   ...:     4: "ZZZZ",
   ...:     12: "XXXX"
   ...: })

In [3]: exp
Out[3]: 'aaaaZZZZcaaaXXXX'
```


### symbols

`symbols` will return a `dotdict` of symbol-to-address mappings. `sym` is a convenience
alias to `symbols`. A `dotdict` is a class within `pwntools` that allows dotted access to the
underlying python `dict`.

```python
In [1]: from pwn import *
In [2]: e = ELF("pwnable")
In [3]: e.symbols
Out[3]:
{u'__gmon_start__': 4207552,
 u'__libc_start_main': 4207544,
 ...snip...
 u'read': 4198480,
 u'setvbuf': 4198512,
 u'stdout': 4207640,
 u'strcmp': 4198496,
 u'strlen': 4198444}

In [4]: e.sym.read
Out[4]: 4198480
```

### search

`search` takes a sequence of bytes and returns an iterator of possible matches. Handy if you want
to get the location of say "/bin/sh" inside of `libc`, or even just to find specific instructions
you might want to use in your payload.

```python
In [1]: from pwn import *
In [2]: e = ELF('/lib/libc.so.6')
In [3]: next(e.search("/bin/sh"))
Out[3]: 1618340
```

Finding a JMP RSP (`ff e4`) instruction:

```python
In [1]: from pwn import *
In [2]: e = ELF('pwnable')
In [3]: next(e.search("\xff\xe4"))
Out[3]: 159281
```

## ROP

The ROP module facilitates creating ROP chains by creating a python-style call API of sorts for
calling symbols located in the binary. We'll use `mprotect` for our example.

From `man 3 mprotect`:

```plaintext
NAME
       mprotect — set protection of memory mapping

SYNOPSIS
       #include <sys/mman.h>
       int mprotect(void *addr, size_t len, int prot);
```

### call

Call will allow you to call the symbol you designate as the first param, and take subsequent
arguments to the callee as a list. The function doesn't return anything, but modifies the
instance of the ROP class. This allows for you to continue to chain more calls together. Once
you're ready, you can `bytes(rop)` or `rop.chain()` to get the resulting payload. As a convenience,
symbols are also directly callable from the `ROP` instance.

```python
In [1]: from pwn import *
In [2]: context.arch = "amd64"
In [3]: rop = ROP('./haxme')

In [4]: rop.dump()
Out[4]: ''

In [5]: rop.call('mprotect', [0x12345678, 0x1000, 0x7])

In [6]: print(rop.dump())
0x0000:         0x43e369 pop rdx; pop rsi; ret
0x0008:              0x7 [arg2] rdx = 7
0x0010:           0x1000 [arg1] rsi = 4096
0x0018:         0x401d93 pop rdi; ret
0x0020:       0x12345678 [arg0] rdi = 305419896
0x0030:         0x43e369 pop rdx; pop rsi; ret

In [7]: rop.read(0, 0x1234, 0x100)

In [8]: print(rop.dump())
0x0000:         0x43e369 pop rdx; pop rsi; ret
0x0008:              0x7 [arg2] rdx = 7
0x0010:           0x1000 [arg1] rsi = 4096
0x0018:         0x401d93 pop rdi; ret
0x0020:       0x12345678 [arg0] rdi = 305419896
0x0028:         0x43bf50 mprotect
####
0x0030:         0x43e369 pop rdx; pop rsi; ret
0x0038:            0x100 [arg2] rdx = 256
0x0040:           0x1234 [arg1] rsi = 4660
0x0048:         0x401d93 pop rdi; ret
0x0050:              0x0 [arg0] rdi = 0
0x0058:         0x43b3e0 read
```

### `gadgets` and `find_gadget`

Upon instantiation of a ROP object, you may see log output mention something like "Loading
Gadgets". It's self explanatory. I do want to mention that `pwntools` gadget finder isn't as
robust as something like 
[ropper](https://github.com/sashs/Ropper).
That said, it's still a very helpful and useful function. `gadgets` contains your dict of gadget
objects and `find_gadget` is simply a convenience methods for searching the `gadgets` dict.

```python
In [1]: from pwn import *
In [2]: rop = ROP('./haxme')

In [3]: len(rop.gadgets)
Out[3]: 109

In [4]: gdt = rop.find_gadget(["pop rsi"])
In [5]: gdt
Out[5]: Gadget(0x4006ab, [u'pop rsi', u'pop r15', u'pop rbp', u'ret'], [u'rsi', u'r15', u'rbp'], 0x10)

In [6]: gdt.address
Out[6]: 4196011L
```


### SROP
When attempting to call something like `mprotect` in a binary that doesn't explicitly have a symbol
for it, `pwntools` will attempt a syscall instead, using SIGRET/SROP. I've written about this
technique in the past.

[Abusing Signals with SIGROP](https://sec.alexflor.es/posts/2019/12/abusing-signals-with-sigrop-exploits/)

Happy refactoring, and see you next time!

