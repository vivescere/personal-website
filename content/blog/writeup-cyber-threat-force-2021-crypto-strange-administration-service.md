---
title: "Writeup Cyber Threat Force : Strange administration service"
date: 2021-07-10T15:55:09+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force", "crypto"]
type: "posts"
showDate: true
---

For this challenge, we were given access to a server which we can connect to:

```bash
$ nc 144.217.73.235 27099

give me cmd|token
example: 
ls|c9af5ac08978481063b711f031f38518a7c2d83d6db3eabacbd7726470e8a140
id|69a4061766769d0a19ab59e6f905f7ac5875691b62765cb6b3b5ee6ae08f776a

ls|c9af5ac08978481063b711f031f38518a7c2d83d6db3eabacbd7726470e8a140
chall.py
wrapper

$ nc 144.217.73.235 27099

give me cmd|token
example: 
ls|c9af5ac08978481063b711f031f38518a7c2d83d6db3eabacbd7726470e8a140
id|69a4061766769d0a19ab59e6f905f7ac5875691b62765cb6b3b5ee6ae08f776a

whoami|c9af5ac08978481063b711f031f38518a7c2d83d6db3eabacbd7726470e8a140
Bad Token
```

It executes the command we give it, given that we know the corresponding hash. The challenge description told us that the hash format is `HASH(SECRET || CMD)`.

This should instantly make us think of [hash key length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks). I've written about this previously, for the [DG'hAck StickItUp challenge](/blog/writeup-dghack-stickitup/).

This attack allows us to append arbitrary data at the end of an hashed value, while keeping the hash valid. Here, we can append ` ; my_command` to the existing command to execute what we want.

We'll use the same tool: [hashpump](https://github.com/bwall/HashPump). First, we have to figure out the key length. The service returned `Bad Token` when we tried to pass the `ls` hash for the `whoami` command, so let's use that.

```python
# To remove warnings from hashpumpy ; https://stackoverflow.com/a/879249/6262617
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning) 

import hashpumpy
from pwn import *

# To remove remote(...) logs
context.log_level = 'ERROR'

ID_HASH = '69a4061766769d0a19ab59e6f905f7ac5875691b62765cb6b3b5ee6ae08f776a'

def get_output(token, command):
    r = remote('144.217.73.235', 27099)
    r.recvuntil(ID_HASH + '\n')
    r.sendline(command + b'|' + token.encode())
    data = r.recvall()
    if b'Bad Token' in data:
        return None
    return data

for key_len in range(100):
    # Could also have used the `ls` hash.
    token, command = hashpumpy.hashpump(ID_HASH, 'id', ' ; echo 1', key_len)
    output = get_output(token, command)

    if output:
        print(key_len, 'OK', output)
        break
    else:
        print(key_len, 'FAIL')
```

```bash
$ python fuzz.py 
0 FAIL
1 FAIL
2 FAIL
3 FAIL
4 FAIL
5 FAIL
6 FAIL
7 FAIL
8 FAIL
9 FAIL
10 FAIL
11 FAIL
12 FAIL
13 FAIL
14 FAIL
15 FAIL
16 FAIL
17 FAIL
18 FAIL
19 FAIL
20 FAIL
21 FAIL
22 OK b'\nuid=1000(ctf) gid=1000(ctf) groups=1000(ctf)\n1\n'
```

As we can see, we successfully injected our `echo 1` command. We get its output right after the output of the `id` command.

We can now build ourselves a simple shell:

```python
# To remove pesky warnings ; https://stackoverflow.com/a/879249/6262617
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning) 

import hashpumpy
from pwn import *

# To remove remote(...) logs
context.log_level = 'ERROR'

ID_HASH = '69a4061766769d0a19ab59e6f905f7ac5875691b62765cb6b3b5ee6ae08f776a'
KEY_LEN = 22

def get_output(token, command):
    r = remote('144.217.73.235', 27099)
    r.recvuntil(ID_HASH + '\n')
    r.sendline(command + b'|' + token.encode())
    data = r.recvall()
    if b'Bad Token' in data:
        return None
    return data

def inject_command(command):
    injected_command = f'; {command}'
    token, command = hashpumpy.hashpump(ID_HASH, 'id', injected_command, KEY_LEN)
    output = get_output(token, command)
    output = output.decode().strip()
    # Remove original 'id' output
    output = '\n'.join(output.split('\n')[1:])
    return output

while True:
    try:
        cmd = input('$ ').strip()
    except:
        break

    if not cmd:
        break

    print(inject_command(cmd))
```

```bash
$ python demo.py
$ whoami
ctf
$ cat /home/ctf/flag.txt
CYBERTF{HM@C_Custom_Is_Bad_Idea}
```

Here we go, the flag is `CYBERTF{HM@C_Custom_Is_Bad_Idea}`.

You can [view the sources on github](https://github.com/vivescere/ctf/tree/main/cyber-threat-force-2021/crypto/strange-administration-service) or [read other writeups](/blog/cyber-threat-force-ctf/).
