---
title: "Writeup Cyber Threat Force : Strange service"
date: 2021-07-10T17:18:09+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force", "crypto"]
type: "posts"
showDate: true
---

For this challenge, we were given access to a service. The description told us that it was an encryption oracle, which used AES to encrypt what we sent it, concatenated with critical data.

I'm writting this after the challenge ended, so I can't include demos.

The description should make us think about byte-at-a-time ECB decryption attacks, which are well explained here:
- [Cryptopals - Byte-a-time ECB decryption (Simple)](https://crypto.stackexchange.com/questions/55673/why-is-byte-at-a-time-ecb-decryption-a-vulnerability)
- [Why is Byte-at-a-time ECB decryption a vulnerability? - Crypto StackExchange](https://crypto.stackexchange.com/questions/55673/why-is-byte-at-a-time-ecb-decryption-a-vulnerability)
- [Cheatsheet - Crypto 101](https://pequalsnp-team.github.io/cheatsheet/crypto-101#encryption-oracle-attack)

I never used this attack before, but heard about it, so I decided to try it. It only works with the ECB mode, which I guessed was what the service was running. I could have [tested this](https://stackoverflow.com/a/20723807/6262617).

The premise is really simple: the ECB mode slices up the data in blocks, which are encrypted separately. Imagine we have `encrypt(input || secret)`. If the block size is 4, what we could do is:

- send `aaa`, and retrieve the first block data ; the first character of the secret will get added to form `'aaa' + secret[0]`,
- send `aaaa`, and compare the first block data with the previous value ; if it matches, the first character of the secret is `a`,
- otherwise, retry with `aaab`, `aaac`, ...

We can script this out:

```python
import string
from pwn import *

context.log_level = 'ERROR'

def service(inp):
    r = remote('144.217.73.235', 29292)
    prompt = r.recvuntil(': ')
    r.sendline(inp)
    output = r.recvall()
    r.close()
    return output

known = b""

while not known.endswith(b'}'):
    # One char short
    l = 64 - 1 - len(known)
    target = service(b'0' * l)[:64]

    for b in string.printable.encode():
        b = bytes([b])
        block = service(known.zfill(64 - 1) + b)[:64]

        if target == block:
            print(b.decode(), end='')
            known += b
            break
    else:
        print()
        break
```

I used 64 chars because that's the size of the returned data. I've failed to retrieve the flag once or twice before because I tried with the block size (16) instead, which only retrieved the start of the secret.

```bash
$ python solve.py
CYBERTF{WTF_It’s_u$eless_in_real_w0rld}
```

The flag was `CYBERTF{WTF_It’s_u$eless_in_real_w0rld}`.

You can [view the sources on github](https://github.com/vivescere/ctf/tree/main/cyber-threat-force-2021/crypto/strange-service) or [read other writeups](/blog/cyber-threat-force-ctf/).
