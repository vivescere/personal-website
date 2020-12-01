---
title: "Writeup DG'hAck: Server Room"
date: 2020-11-19T05:00:05+01:00
draft: false
tags: ["blog", "security", "ctf", "dghack"]
type: "posts"
showDate: true
---

This challenge starts with a file, `found_in_server_room.img.gz`. Let's first try to find what this file is:

```bash
$ gunzip found_in_server_room.img.gz
$ file found_in_server_room.img
found_in_server_room.img: DOS/MBR boot sector; partition 1 : ID=0xc, start-CHS (0x40,0,1), end-CHS (0x3ff,3,32), startsector 8192, 524288 sectors; partition 2 : ID=0x83, start-CHS (0x3ff,3,32), end-CHS (0x3ff,3,32), startsector 532480, 3072000 sectors
```

So this is a disk image. Let's try mounting it!

```bash
$ mkdir mnt
$ sudo mount found_in_server_room.img mnt
NTFS signature is missing.
Failed to mount '/dev/loop0': Invalid argument
The device '/dev/loop0' doesn't seem to have a valid NTFS.
Maybe the wrong device is used? Or the whole disk instead of a
partition (e.g. /dev/sda, not /dev/sda1)? Or the other way around?
```

Huh.

```bash
$ fdisk -l found_in_server_room.img
Disk found_in_server_room.img: 1.72 GiB, 1845493248 bytes, 3604479 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x907af7d0

Device                    Boot  Start     End Sectors  Size Id Type
found_in_server_room.img1        8192  532479  524288  256M  c W95 FAT32 (LBA)
found_in_server_room.img2      532480 3604479 3072000  1.5G 83 Linux
```

fdisk does find the partitions, but for some reason we can't mount them (even by setting the offset). Using testdisk, we're able to navigate through the files by selecting:

 - `found_in_server_room.img`
 - Intel
 - Advanced
 - The first or the second partition
 - Boot > List or just List

The first partition does not contain anything useful, just necessary boot files. The other partition is a typical linux root:

[![The linux partition](/assets/dghack/server-room-root.png)](/assets/dghack/server-room-root.png)

The first thing that comes to mind is to check the `.bash_history`. The one of the `pi` user is rather empty:

```bash
sudo systemctl halt
```

But the one of the `root` user contains quite a few commands (76 of them, to be exact). Here are the ones where nano is used:

```bash
nano wpa_supplicant.conf
nano hostapd
nano /etc/sysctl.d/90-routing.conf
nano /etc/dnsmasq.conf 
nano /etc/dhcpcd.conf 
nano /etc/dnsmasq.conf 
nano /etc/wpa_supplicant/wpa_supplicant.conf
nano /etc/wpa_supplicant/wpa_supplicant.conf
nano /etc/wpa_supplicant/wpa_supplicant.conf.old 
nano /etc/dnsmasq.conf 
nano /etc/hostapd/hostapd.conf
```

The `wpa_supplicant.conf` file does not yield anything too interesting:

```
1598621524 02:6c:0d:3b:04:17 192.168.100.171 OnePlus5T 01:02:6c:0d:3b:04:17
```

But the `hostapd.conf` one does:

```
country_code=FR
interface=wlan0
ssid=BackpackNet
hw_mode=g
channel=11
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=BackpackBackdoorNet
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
```

The flag is the wifi password: `BackpackBackdoorNet`.

---

[View all of the DG'hAck articles](/tags/dghack).
