---
title: "Writeup DG'hAck: Involucrypt 2"
date: 2020-12-01T04:11:32+01:00
draft: false
tags: ["blog", "security", "ctf", "dghack"]
type: "posts"
showDate: true
---

This is the second version of the involucrypt challenge. You can see my writeup of the first version [here](/blog/writeup-dghack-involucrypt-1/). It presents the encryption script and a simple bruteforce approach.

The only thing that changed for the second version is the encrypted data, which is now `1497` bytes long. This makes the previous bruteforce attempt unusable: checking a single key takes about 50ms on my machine, and there are a lot of possible keys (since it's 10 chars instead of 3).

After looking at the code, the only weird thing I found was the `base` parameter:

```python
def keystream(seeds, length, base=None):
    key = base if base else []
    for seed in seeds:
        random = mersenne_rng(seed)

        for _ in range(BLOCK):
            if len(key) == length:
                break
            key.append(random.get_rand_int(0, 255))
            random.shuffle(key)
        if len(key) == length:
            break
    return key
```

It's not used anywhere! It allows the keystream function to "resume" itself: to add blocks at the end of an already generated keystream.

At first glance, it might seem like it would be a great way to speedup the bruteforce. And it is! But there are still way too many possibilities (`26^10` or `141167095653376`, if we assume the key is still made up of lowercase letters).

The thing that you had to notice was the way the blocks are shuffled. Let's look at an example.

We'll take a message that's 6 bytes long, and a block size of 2.

```python
>>> key = list(map(ord, 'key'))
>>> BLOCK = 2

>>> # First, let's try to encode the whole message:
>>> keystream(key, 6)
[167, 23, 61, 97, 12, 201]

>>> # Then, let's generate the blocks on after another:
>>> keystream(key, 2)
[23, 97]
>>> keystream(key, 4)
[97, 201, 23, 61]
>>> keystream(key, 6)
[167, 23, 61, 97, 12, 201]

# Now let's use the base param to do the same thing, but starting from the
# last block (using zeros as padding).
>>> keystream(key[-1:], 6, base=[0] * BLOCK * 2)
[167, 0, 0, 0, 12, 0]
>>> keystream(key[-2:], 6, base=[0] * BLOCK * 1)
[167, 0, 61, 0, 12, 201]
>>> keystream(key[-3:], 6, base=[0] * BLOCK * 0)
[167, 23, 61, 97, 12, 201]
```

Noticed something? When starting from the last block, the integers are in the right place. This allows us to try and decrypt the bytes, and then by simply checking if the characters are valid or not determine the last letter of the key. We can then repeat this process for the penultimate block, and up until we reach the first one.

We can use this simple trick to reduce the space we need to search from `26^10` to `26*10`. This is way better! Let's write a script:

```python
import sys
import math
import string
import operator
import itertools

# Note: I renamed the script `crypt.py` to `ccrypt.py`, to avoid naming issues.
from ccrypt import keystream, BLOCK


def encrypt(string, key, base):
    key = keystream(map(ord, key), len(string), base)
    stream = itertools.starmap(operator.xor, zip(key, string))
    return list(stream)


data = open(sys.argv[1], "rb").read()
block_count = math.ceil(len(data) / BLOCK)
password = ""

print("Key: " + "*" * block_count, end="\r")

for block in range(block_count - 1, -1, -1):
    guesses = []

    for guess in string.ascii_lowercase:
        key = guess + password

        decrypted = encrypt(data, key, bytearray(bytes(BLOCK * block)))
        valid_count = sum(1 for c in decrypted if chr(c) in string.printable)

        guesses.append((key, decrypted, valid_count))

    password, _, _ = max(guesses, key=lambda x: x[2])
    print("Key: " + "*" * block + password, end="\r")

print("\nContent:")

decoded = "".join(
    chr(a ^ b) for a, b in zip(data, keystream(map(ord, password), len(data)))
)
print(decoded)
```

And run it:

```
$ pypy3 brute3.py involucrypt2
Key: ajjfisptoi
Content:
It's something about ya girl,
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
that just makes my head wanna twirl,
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
oh you got me want to tell all them other girls,
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
there's nothing else better in this world!
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
the moment i seen her i was in shock
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
so shocked you would've think I've just been shot,
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
shot down right now in this spot.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
But too bad this doesn't happen a lot.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Oh girl you got me visualizing me on top,
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
on top of your hot body while were sweating a lot,
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
a lot of time on the clock before we have to stop.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
too bad shes not into that stuff a lot,
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
oh man shes really super hot,
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
hotter than the sun that's right on top,
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Oh man there she goes i had to stop,
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
and ask her some questions that i had in stock.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
She said she want's to take it slow,
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
i'm not that type of guy ill let cha know,
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
when i see that red light all i know is go,
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
so baby girl lets do this on the floor.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
show me your moves that makes you such a pro


*the flag is supahotfire*
```

This took 10 seconds on my machine (thanks to [pypy3](https://www.pypy.org/)), which is really short. The key is `ajjfisptoi`, and the flag is `supahotfire`.

Note: running the new script on `involucrypt1` successfully decrypts it in about half a second, which is a nice speedup.

---

[View all of the DG'hAck articles](/tags/dghack).
