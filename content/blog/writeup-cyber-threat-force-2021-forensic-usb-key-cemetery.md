---
title: "Writeup Cyber Threat Force : Usb key cemetery"
date: 2021-07-11T09:09:09+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force", "forensic"]
type: "posts"
showDate: true
---

Note: I did not solve this challenge during the CTF, but my teammate [Volker](https://twitter.com/volker_carstein) did.

For this challenge, we were given a zip containing an encoded syslog (`sysloc.enc`), and an `auth.json` file:

```json
{
    "manufact": [
        "Apple Inc.",
        "Azurewave",
        "Generic",
        "Linux 5.10.0-kali8-amd64 xhci-hcd",
        "usbrip-4381"
    ],
    "pid": [
        "0002",
        "0003",
        "0129",
        "0608",
        "12a8",
        "3491",
        "56dd",
        "usbrip-4381"
    ],
    "prod": [
        "USB2.0 HD UVC WebCam",
        "USB2.0 Hub",
        "USB2.0-CRW",
        "iPhone",
        "usbrip-4381",
        "xHCI Host Controller"
    ],
    "serial": [
        "0000:03:00.3",
        "0000:03:00.4",
        "0x0001",
        "20100201396000000",
        "4b8d611f609abfc5471ae40d08d0c8b785eab9d4",
        "usbrip-4381"
    ],
    "vid": [
        "05ac",
        "05e3",
        "0bda",
        "13d3",
        "1d6b",
        "usbrip-4381"
    ]
}
```

The goal of the challenge is to find the serial number of the rubber ducky which was connected to the machine for which we have the syslog.

```bash
$ file syslog.enc
syslog.enc: data
````

The file doesn't look like any well known format, so we can assume (quite safely) that the encryption is a simple XOR. We'll use [the known plaintext XOR tool from Didier Stevens](https://blog.didierstevens.com/2016/01/01/xor-known-plaintext-attack/).

A good candidate for the plaintext is `Linux 5.10.0-kali8-amd64 xhci-hcd`, which will surely appear.

```bash
$ python2 xor-kpa.py -d <(echo 'Linux 5.10.0-kali8-amd64 xhci-hcd') syslog.enc > syslog
$ head -n 5 syslog
Jun  7 22:53:25 kali usbmuxd[117991]: [22:53:25.287][3] Connecting to new device on location 0x10004 as ID 1
Jun  7 22:53:25 kali usbmuxd[117991]: [22:53:25.287][3] Connected to v2.0 device 1 on location 0x10004 with serial number 4b8d611f609abfc5471ae40d08d0c8b785eab9d4
Jun  7 22:53:27 kali ModemManager[830]: <info>  [base-manager] couldn't check support for device '/sys/devices/pci0000:00/0000:00:08.1/0000:03:00.3/usb1/1-2': not supported by any plugin
Jun  8 00:16:16 kali lynis[144261]: - usbmuxd.service: [ UNSAFE ]
Jun  8 00:16:22 kali lynis[118776]: - Checking usb-storage driver (modprobe config) [ NON DESACTIVÉ ]
```

That seems like a valid syslog! After looking for a short while, we find:

```
Apr 12 20:21:25 kali kernel: [    1.830063] usb 1-2: Product: Fake_KeyBoard
Apr 12 20:21:25 kali kernel: [    1.830064] usb 1-2: Manufacturer: APT43.
Apr 12 20:21:25 kali kernel: [    1.830065] usb 1-2: SerialNumber: 854be9ee57ef47ce74e73904998d61c8846e9239
```

The flag is `CYBERTF{854be9ee57ef47ce74e73904998d61c8846e9239}`.

You can [view the sources on github](https://github.com/vivescere/ctf/tree/main/cyber-threat-force-2021/forensic/usb-key-cemetery) or [read other writeups](/blog/cyber-threat-force-ctf/).
