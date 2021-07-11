---
title: "Writeup Cyber Threat Force : Take your time"
date: 2021-07-08T23:01:09+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force", "reverse"]
type: "posts"
showDate: true
---

For this challenge, we were given a `TakeYourTime` executable, which seems to hang when we run it. We can analyze its code using ghidra:

```c
unsigned int FLAG[] = {
  0xb5, 0x63, 0x98, 0x3d,
  0xb5, 0x06, 0x46, 0xba,
  0x0f, 0xd5, 0x47, 0xce,
  0x97, 0xef, 0x7b, 0x28,
  0xdb, 0xe7, 0x39, 0x10,
  0xb0, 0xf5, 0x44, 0xec,
  0x30, 0x88, 0x46, 0xf6,
  0x88,
};

undefined8 main(void) {
  byte bVar1;
  int iVar2;
  uint local_28;
  int local_24;
  ulong local_20;
  
  local_28 = 0;
  local_20 = 0x32;
  while (local_20 < 0x4f) {
    bVar1 = fibonacci();
    local_28 = local_28 >> 8 | (local_28 ^ bVar1) << 0x18;
    local_20 = local_20 + 1;
  }
  srand(local_28);
  local_24 = 0;
  while (local_24 < 0x1d) {
    bVar1 = FLAG[local_24];
    iVar2 = rand();
    putchar((uint)bVar1 ^ iVar2 % 0xff);
    local_24 = local_24 + 1;
  }
  puts("\nGood you can validate the chall with this password ;)!");
  return 0;
}

long fibonacci(long param_1) {
  long lVar1;
  long lVar2;
  
  if (param_1 == 0) {
    lVar1 = 0;
  }
  else {
    if (param_1 == 1) {
      lVar1 = 1;
    }
    else {
      lVar2 = fibonacci(param_1 + -1);
      lVar1 = fibonacci(param_1 + -2);
      lVar1 = lVar1 + lVar2;
    }
  }
  return lVar1;
}
```

What's happening there is that the program takes too long to execute: the fibonacci implementation is a naive one (recursive).

Let's be as lazy as possible and rewrite the program hardcoding the values that are needed:

```c
#include <stdio.h>
#include <stdlib.h>

unsigned int fibo(unsigned int param) {
    if (param == 50) return 12586269025;
    if (param == 51) return 20365011074;
    if (param == 52) return 32951280099;
    if (param == 53) return 53316291173;
    if (param == 54) return 86267571272;
    if (param == 55) return 139583862445;
    if (param == 56) return 225851433717;
    if (param == 57) return 365435296162;
    if (param == 58) return 591286729879;
    if (param == 59) return 956722026041;
    if (param == 60) return 1548008755920;
    if (param == 61) return 2504730781961;
    if (param == 62) return 4052739537881;
    if (param == 63) return 6557470319842;
    if (param == 64) return 10610209857723;
    if (param == 65) return 17167680177565;
    if (param == 66) return 27777890035288;
    if (param == 67) return 44945570212853;
    if (param == 68) return 72723460248141;
    if (param == 69) return 117669030460994;
    if (param == 70) return 190392490709135;
    if (param == 71) return 308061521170129;
    if (param == 72) return 498454011879264;
    if (param == 73) return 806515533049393;
    if (param == 74) return 1304969544928657;
    if (param == 75) return 2111485077978050;
    if (param == 76) return 3416454622906707;
    if (param == 77) return 5527939700884757;
    if (param == 78) return 8944394323791464;
    return -1;
}

int main(void) {
        unsigned int FLAG[] = {
                0xb5, 0x63, 0x98, 0x3d,
                0xb5, 0x06, 0x46, 0xba,
                0x0f, 0xd5, 0x47, 0xce,
                0x97, 0xef, 0x7b, 0x28,
                0xdb, 0xe7, 0x39, 0x10,
                0xb0, 0xf5, 0x44, 0xec,
                0x30, 0x88, 0x46, 0xf6,
                0x88,
        };

        unsigned int seed = 0;

        for (unsigned int i = 0x32; i < 0x4f; i++) {
                unsigned int res = fibo(i);
                seed = seed >> 8 | (seed ^ res) << 0x18;
        }

        srand(seed);

        for (unsigned int i2 = 0; i2 < 0x1d; i2++) {
                unsigned int res = FLAG[i2];
                putchar((unsigned int) res ^ rand() % 0xff);
        }

        puts("\n");
        return 0;
}
```

```bash
$ gcc solve.c -o solve
... (lots of warnings)

$ ./solve
CYBERTF{Fuck_Fibo_3v3ryWhere}
```

Here we go, the flag is `CYBERTF{Fuck_Fibo_3v3ryWhere}`.

You can [view the sources on github](https://github.com/vivescere/ctf/tree/main/cyber-threat-force-2021/reverse/take-your-time) or [read other writeups](/blog/cyber-threat-force-ctf/).

