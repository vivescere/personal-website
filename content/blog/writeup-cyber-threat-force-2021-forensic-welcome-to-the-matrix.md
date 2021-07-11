---
title: "Writeup Cyber Threat Force : Welcome to the matrix"
date: 2021-07-09T22:31:09+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force", "forensic"]
type: "posts"
showDate: true
---

For this challenge, we were given a pcapng file. The flag is meant to be `CYBERTF{c2 framework used in leet speak}`. Running strings on the capture, we see:

```bash
$ strings c2.pcapng
...
3d77
7o0~
b|}p
l69s
Covenant0
210520070857Z
310519070857Z0
Covenant0
~vVz"/
loq5
...
```

[Covenant](https://github.com/cobbr/Covenant) is a well known C2 framework. The flag is `CYBERTF{C0V3N4NT}`.

You can [view the sources on github](https://github.com/vivescere/ctf/tree/main/cyber-threat-force-2021/forensic/welcome-to-the-matrix) or [read other writeups](/blog/cyber-threat-force-ctf/).
