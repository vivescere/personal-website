---
title: "Writeup DG'hAck: Bwing"
date: 2020-11-30T07:19:09+01:00
draft: false
tags: ["blog", "security", "ctf", "dghack"]
type: "posts"
showDate: true
---

For this challenge, we're given a `dump.raw` file, which we're told is a memory dump. We have to find confidential data in it.

First, let's see what kind of image this is:

```bash
$ volatility -f dump.raw imageinfo
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : No suggestion (Instantiated with no profile)
                     AS Layer1 : FileAddressSpace (/home/vivescere/Projects/dghack/bwing/dump.raw)
                      PAE type : No PAE
```

None of the default profiles seem to work, we'll have to create our own. First, let's find out about the linux version:

```bash
$ strings dump.raw | grep -i 'linux version' 
Linux version 4.15.0-66-generic (buildd@lgw01-amd64-044) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #75-Ubuntu SMP Tue Oct 1 05:24:09 UTC 2019 (Ubuntu 4.15.0-66.75-generic 4.15.18)
Linux version 4.15.0-66-generic (buildd@lgw01-amd64-044) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #75-Ubuntu SMP Tue Oct 1 05:24:09 UTC 2019 (Ubuntu 4.15.0-66.75-generic 4.15.18)
Linux version 4.15.0-66-generic (buildd@lgw01-amd64-044) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #75-Ubuntu SMP Tue Oct 1 05:24:09 UTC 2019 (Ubuntu 4.15.0-66.75-generic 4.15.18)
 o  The intent is to make the tool independent of Linux version dependencies,
    On some Linux version, write-only pipe are detected as readable. This
 o  The intent is to make the tool independent of Linux version dependencies,
    On some Linux version, write-only pipe are detected as readable. This
    On some Linux version, write-only pipe are detected as readable. This
        0045  Raptor 4000-L [Linux version]
        004a  Raptor 4000-LR-L [Linux version]
Nov  6 09:47:15 ubuntu-bionic kernel: [    0.000000] Linux version 4.15.0-66-generic (buildd@lgw01-amd64-044) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #75-Ubuntu SMP Tue Oct 1 05:24:09 UTC 2019 (Ubuntu 4.15.0-66.75-generic 4.15.18)
Nov  6 09:47:15 ubuntu-bionic kernel: [    0.000000] Linux version 4.15.0-66-generic (buildd@lgw01-amd64-044) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #75-Ubuntu SMP Tue Oct 1 05:24:09 UTC 2019 (Ubuntu 4.15.0-66.75-generic 4.15.18)
00000] Linux version 4.15.0-66-generic (buildd@lgw01-amd64-044) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #75-Ubuntu SMP Tue Oct 1 05:24:09 UTC 2019 (Ubuntu 4.15.0-66.75-generic 4.15.18)
MESSAGE=Linux version 4.15.0-66-generic (buildd@lgw01-amd64-044) (gcc version 7.4.0 (Ubuntu 7.4.0-1ubuntu1~18.04.1)) #75-Ubuntu SMP Tue Oct 1 05:24:09 UTC 2019 (Ubuntu 4.15.0-66.75-generic 4.15.18)
SWIMS: Linux Version: %04X
```

So it's an Ubuntu 18.04.1, with the 4.15.0-66-generic kernel. We can find the image on the [old-releases.ubuntu.com](http://old-releases.ubuntu.com/releases/18.04.1/ubuntu-18.04-desktop-amd64.iso) website. After booting up a VM and installing the system, we'll install the kernel we want:

```bash
$ sudo su
$ apt install linux-image-4.15.0-66-genericlinux-headers-4.15.0-66-generic
$ reboot
```

And create the profile:

```bash
$ sudo su
$ apt install volatility-tools build-essential linux-headers-4.15.0-66-generic
$ cd /usr/src/volatility-tools/linux
$ make
$ zip ubuntu_custom.zip module.dwarf /boot/System.map-4.15.0-66-generic
```

After getting the profile from the VM, we have to load it:

```bash
$ cp ubuntu_custom.zip /usr/lib/python2.7/site-packages/volatility/plugins/overlays/linux/ubuntucustom.zip
$ volatility --info | grep ubuntu
Volatility Foundation Volatility Framework 2.6.1
Linuxubuntucustomx64  - A Profile for Linux ubuntucustom x64
```

We can finally get to work, after trying to list the processes, let's try to list the mounts:

```bash
$ volatility --profile=Linuxubuntucustomx64 -f dump.raw linux_mount          
Volatility Foundation Volatility Framework 2.6.1
cgroup                    /sys/fs/cgroup/rdma                 cgroup       ro,relatime,nosuid,nodev,noexec                                   
/dev/sda1                 /                                   ext4         ro,relatime                                                       
tmpfs                     /sys/fs/cgroup                      tmpfs        ro,nosuid,nodev,noexec                                            
cgroup                    /sys/fs/cgroup/freezer              cgroup       rw,relatime,nosuid,nodev,noexec                                   
devpts                    /dev/pts                            devpts       rw,relatime,nosuid,noexec                                         
securityfs                /sys/kernel/security                securityfs   rw,relatime,nosuid,nodev,noexec                                   
ramfs                     /mnt/confidential                   ramfs        rw,relatime                                                       
systemd-1                 /proc/sys/fs/binfmt_misc            autofs       rw,relatime                                                       
cgroup                    /sys/fs/cgroup/blkio                cgroup       rw,relatime,nosuid,nodev,noexec                                   
cgroup                    /sys/fs/cgroup/pids                 cgroup       ro,relatime,nosuid,nodev,noexec                                   
udev                      /dev                                devtmpfs     rw,relatime,nosuid                                                
tmpfs                     /run/lxcfs/controllers              tmpfs        rw,relatime                                                       
cpuset                    /run/lxcfs/controllers/cpuset       cgroup       rw,relatime                                                       
sysfs                     /sys                                sysfs        ro,relatime,nosuid,nodev,noexec                                   
cgroup                    /sys/fs/cgroup/unified              cgroup2      rw,relatime,nosuid,nodev,noexec                                   
devices                   /run/lxcfs/controllers/devices      cgroup       rw,relatime                                                       
memory                    /run/lxcfs/controllers/memory       cgroup       rw,relatime                                                       
cgroup                    /sys/fs/cgroup/systemd              cgroup       rw,relatime,nosuid,nodev,noexec                                   
tmpfs                     /lib/modules/dir                    tmpfs        ro,relatime,nosuid,noexec                                         
vagrant                   /vagrant                            vboxsf       rw,relatime,nodev                                                 
pstore                    /sys/fs/pstore                      pstore       rw,relatime,nosuid,nodev,noexec                                   
cgroup                    /sys/fs/cgroup/hugetlb              cgroup       ro,relatime,nosuid,nodev,noexec                                   
mqueue                    /dev/mqueue                         mqueue       rw,relatime                                                       
fusectl                   /sys/fs/fuse/connections            fusectl      rw,relatime                                                       
proc                      /proc                               proc         rw,relatime,nosuid,nodev,noexec                                   
debugfs                   /sys/kernel/debug                   debugfs      rw,relatime                                                       
cgroup                    /sys/fs/cgroup/net_cls,net_prio     cgroup       rw,relatime,nosuid,nodev,noexec                                   
lxcfs                     /var/lib/lxcfs                      fuse         rw,relatime,nosuid,nodev                                          
hugetlbfs                 /dev/hugepages                      hugetlbfs    rw,relatime                                                       
configfs                  /sys/kernel/config                  configfs     ro,relatime                                                       
cgroup                    /sys/fs/cgroup/perf_event           cgroup       rw,relatime,nosuid,nodev,noexec                                   
tmpfs                     /dev/shm                            tmpfs        rw,nosuid,nodev                                                   
tmpfs                     /run/lock                           tmpfs        rw,relatime,nosuid,nodev,noexec                                   
cgroup                    /sys/fs/cgroup/cpu,cpuacct          cgroup       rw,relatime,nosuid,nodev,noexec                                   
tmpfs                     /dev                                tmpfs        ro,nosuid,noexec
```

The `/mnt/confidential` folder is particularly interesting, let's try to find files in it:

```bash
$ volatility --profile=Linuxubuntucustomx64 -f dump.raw linux_enumerate_files | grep '/mnt/confidential'
Volatility Foundation Volatility Framework 2.6.1
0xffff95a89ac58528                    256033 /mnt/confidential
0xffff95a89ac74000                     22086 /mnt/confidential
0xffff95a89ac72260                     22114 /mnt/confidential/flag.txt

$ volatility --profile=Linuxubuntucustomx64 -f dump.raw linux_find_file -i 0xffff95a89ac72260 -O flag.txt
Volatility Foundation Volatility Framework 2.6.1

$ cat flag.txt 
C0D3N4M34P011011
```

The flag is `C0D3N4M34P011011`.

---

[View all of the DG'hAck articles](/tags/dghack).
