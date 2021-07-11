---
title: "Cyber Threat Force (CTF)"
date: 2021-07-11T10:12:19+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force"]
type: "posts"
showDate: true
---

This was a short CTF (48h), a format that I like since it doesn't eat up too much of my time. I enjoyed it with my friends: [Lukho](https://twitter.com/lukhooo), [R0ck3t](https://ctftime.org/user/46515) and [Volker](https://twitter.com/volker_carstein). We registered a team on CTFTime: [Root Root](https://ctftime.org/team/157632).

We ranked 4th out of 197 teams, scoring 6935 points. And I personnaly ranked 6th, scoring 3775 points and completing 19 challenges!

Here are the challenges that I completed or spent time on, with links to my writeups:

- Pwn
	- [PrivEsc](/blog/writeup-cyber-threat-force-2021-pwn-privesc/)
	- [Bof 1](/blog/writeup-cyber-threat-force-2021-pwn-bof-1/)
	- [Bof 1 GetShell](/blog/writeup-cyber-threat-force-2021-pwn-bof-1/#level-2-getshell)
	- [Bof 1 PrivEsc](/blog/writeup-cyber-threat-force-2021-pwn-bof-1/#level-3-privesc)
	- [Bof 2](/blog/writeup-cyber-threat-force-2021-pwn-bof-2/)
	- [Bof 2 PrivEsc](/blog/writeup-cyber-threat-force-2021-pwn-bof-2/#level-2-privesc)
	- [Bof 3](/blog/writeup-cyber-threat-force-2021-pwn-bof-3/)
- Reverse
	- [Take your time](/blog/writeup-cyber-threat-force-2021-reverse-take-your-time/)
	- [Flag checker](/blog/writeup-cyber-threat-force-2021-reverse-flag-checker/)
	- [Verify this](/blog/writeup-cyber-threat-force-2021-reverse-verify-this/) (almost solved)
	- [Smasher](/blog/writeup-cyber-threat-force-2021-reverse-smasher/) (flagged by [R0ck3t](https://ctftime.org/user/46515))
	- [The document is strange](/blog/writeup-cyber-threat-force-2021-reverse-the-document-is-strange/)
	- [Viking crypt](/blog/writeup-cyber-threat-force-2021-reverse-viking-crypt/)
	- [Trojan tools](/blog/writeup-cyber-threat-force-2021-reverse-trojan-tools/)
- Crypto
	- [Strange administration service](/blog/writeup-cyber-threat-force-2021-crypto-strange-administration-service/)
	- [Strange service](/blog/writeup-cyber-threat-force-2021-crypto-strange-service/)
	- [(Un)Efficient encryption](/blog/writeup-cyber-threat-force-2021-crypto-unefficient-encryption/)
- Forensic
	- [Welcome to the matrix](/blog/writeup-cyber-threat-force-2021-forensic-welcome-to-the-matrix/)
	- [Usb key cemetery](/blog/writeup-cyber-threat-force-2021-forensic-usb-key-cemetery/) (flagged by [Volker](https://twitter.com/volker_carstein))
	- [Like a duck in water](/blog/writeup-cyber-threat-force-2021-forensic-like-a-duck-in-water/) (flagged by [Lukho](https://twitter.com/lukhooo))
- Steganography
	- Strange file
- Discord
	- Discord as a C2
- Misc
	- [Return to the school](/blog/writeup-cyber-threat-force-2021-misc-return-to-the-school/)
	- [Azkaban C2](/blog/writeup-cyber-threat-force-2021-misc-azkaban-c2/)

I think I improved quite a bit compared to my previous CTF, but I'm still not good enough at binary exploitation and reverse engineering ; I should have been a lot quicker for many challenges. That would have meant more time to discover the lab, which I didn't really have time for. Guess I'll go back to root-me for now!

## Links

- [Official website](https://cyberthreatforce-ctf.com/index.html)
- [CTFTime event](https://ctftime.org/event/1380)
- [My repo with the sources](https://github.com/vivescere/ctf)
- Other writeups that I found:
	- [AetherBlack](https://github.com/AetherBlack/CyberThreatForce2021)
	- [MikeCAT](https://qiita.com/mikecat_mixc/items/c8ce09f484b81480e5ae)
	- [Electro](https://hackmd.io/@Electro/CyberThreatForce-2021)
	- [Amendil](https://ctftime.org/writeup/29113)
	- [W0rty](https://github.com/W0rty/WU-CyberThreatForce/)
	- [UVision](https://hackmd.io/@ZIHK9sOKRKWawlEr3aTZYw/Byb0w5y6_)
	- [Cieran](https://github.com/cieran/writeups/tree/main/CyberThreatForceCTF)
	- [Avilia](https://hanasuru.medium.com/how-we-found-unintended-bypass-to-exploiting-entire-cyberthreatforce-discord-server-d93951b9efab)
	- [LightDiscord](https://gist.github.com/lightdiscord/d8b087c469b65f67f0762bfee2d48320)

## Screenshots

The teams scoreboard:
[![The scoreboard showing the top teams](/assets/cyber-threat-force/scoreboard-teams.png)](/assets/cyber-threat-force/scoreboard-teams.png)

The players scoreboard:
[![The scoreboard showing the top players](/assets/cyber-threat-force/scoreboard-individuals.png)](/assets/cyber-threat-force/scoreboard-individuals.png)

My CTFd profile:
[![My CTFd profile showing the challenges I completed](/assets/cyber-threat-force/profile.png)](/assets/cyber-threat-force/profile.png)
