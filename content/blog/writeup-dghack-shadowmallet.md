---
title: "Writeup DG'hAck: Shadowmallet"
date: 2020-11-28T06:44:23+01:00
draft: false
tags: ["blog", "security", "ctf", "dghack"]
type: "posts"
showDate: true
---

This challenge starts with a file called `shadowmallet`. We're asked to help an administrator whose server detected an abnormal activity.

The `file` command doesn't give us anything:

```bash
$ file shadowmallet 
shadowmallet: data
```

But searching for the first few bytes (`53ff 00f0 53ff 00f0 53ff 00f0 53ff 00f0`) of the file online quickly reveals it's a memory dump. Let's use volatility!

```bash
$ volatility -f shadowmallet imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : No suggestion (Instantiated with Linuxdebiancustomx64)
                     AS Layer1 : FileAddressSpace (/home/vivescere/Projects/dghack/shadow-mallet/shadowmallet)
                      PAE type : No PAE
                           DTB : -0x1L
```

No dice with the default profiles. We'll have to create a custom one.

## Creating the profile

First, let's find out the linux version (I guessed that it was a linux machine):

```bash
$ strings shadowmallet | grep -i 'linux version'
        0045  Raptor 4000-L [Linux version]
        004a  Raptor 4000-LR-L [Linux version]
Nov  9 17:30:13 contrib-buster kernel: [    0.000000] Linux version 4.19.0-9-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.118-2 (2020-04-29)
Nov  9 17:30:13 contrib-buster kernel: [    0.000000] Linux version 4.19.0-9-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.118-2 (2020-04-29)
Nov  9 17:30:13 contrib-buster kernel: [    0.000000] Linux version 4.19.0-9-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.118-2 (2020-04-29)
Raptor 4000-L [Linux version]
Raptor 4000-LR-L [Linux version]
Linux version 4.19.0-9-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.118-2 (2020-04-29)
Linux version 4.19.0-9-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.118-2 (2020-04-29)
SWIMS: Linux Version: %04X
MESSAGE=Linux version 4.19.0-9-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.118-2 (2020-04-29)
```

Now, finding the right image is a bit tricky. I tried three ISOs before finally finding the right one. At first, seeing `Debian 8.3.0-6`. I thought that it was a Debian 8 machine. But this is the version of debian on which gcc was compiled.

To find the right ISO, you had to notice:

- `contrib-buster`, Buster being the codename for Debian 10
- `2020-04-29`, which gives a pretty good hint about what version to use

Here are the available Buster images:

[![The list of Debian 10 isos](/assets/dghack/shadowmallet-isos.png)](/assets/dghack/shadowmallet-isos.png)

The closest one to the date is debian 10.4.0, which is the image we're going to use. The next step is to download [the ISO (live version)](https://cdimage.debian.org/mirror/cdimage/archive/10.4.0-live/amd64/iso-hybrid/debian-live-10.4.0-amd64-standard.iso), boot it in a VM, and generate the profile:

```bash
$ sudo su

# We can check that we have the right version
$ dmesg | head -n 1
[    0.000000] Linux version 4.19.0-9-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.118-2 (2020-04-29)

# And then generate the profile
$ apt install volatility-tools build-essential zip
$ cd /usr/src/volatility-tools/linux
$ make
$ zip debian_custom.zip module.dwarf /boot/System.map-4.19.0-9-amd64
```

After getting the profile back to our host system, we have to load it:

```bash
$ cp debian_custom.zip /usr/lib/python2.7/site-packages/volatility/plugins/overlays/linux/debiancustom.zip
$ volatility --info | grep debian
Volatility Foundation Volatility Framework 2.6.1
Linuxdebiancustomx64  - A Profile for Linux debiancustom x64
```

## Analyzing the image

At first glance, there doesn't seem to be anything suspicious going on:

- no weird processes are running
- no suspicious files are present
- reading the logs don't reveal anything... or at least I thought so

I'm not sure how we were supposed to find this, but after trying a lot of the available commands, I discovered:

```bash
$ volatility --profile=Linuxdebiancustomx64 -f shadowmallet linux_hidden_modules
Volatility Foundation Volatility Framework 2.6.1
Offset (V)         Name
------------------ ----
0xffffffffc04a6000 netfilter
0xffffffffc0578300 qni
```

The netfilter module may be interesting, so let's dump it:
```bash
$ volatility --profile=Linuxdebiancustomx64 -f shadowmallet linux_moddump -b 0xffffffffc04a6000 -D .
Volatility Foundation Volatility Framework 2.6.1
Wrote 668514 bytes to netfilter.0xffffffffc04a6000.lkm

$ file netfilter.0xffffffffc04a6000.lkm 
netfilter.0xffffffffc04a6000.lkm: ELF 64-bit LSB relocatable, Intel 80386, version 1 (SYSV), BuildID[sha1]=43d8d77459d809b0337cbd723733ac10f8b582e8, not stripped

$ strings -n 10 netfilter.0xffffffffc04a6000.lkm | head -n 10
4.19.0-9-amd64
[]A\A]A^A_
[]A\A]A^A_
YES SHA1 is CORRECT
B3tterR=H1deMebeTT3r=then!Right?
hook.cold.5
__func__.5155
__this_module
SHA1Update
cleanup_module
```

And we find the flag, `B3tterR=H1deMebeTT3r=then!Right?`. I guess we were supposed to find this using `dmesg`:
```bash
$ volatility --profile=Linuxdebiancustomx64 -f shadowmallet linux_dmesg | grep netfilter
Volatility Foundation Volatility Framework 2.6.1
[1605821327.1] netfilter: loading out-of-tree module taints kernel.
[1605836480.1] netfilter: module verification failed: signature and/or required key missing - tainting kernel
```

Or maybe, since I see the string `YES SHA1 is CORRECT`, using a SHA1 hash?

---

[View all of the DG'hAck articles](/tags/dghack).
