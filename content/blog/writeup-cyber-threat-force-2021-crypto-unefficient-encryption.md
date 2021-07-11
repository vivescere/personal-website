---
title: "Writeup Cyber Threat Force : (Un)Efficient encryption"
date: 2021-07-10T23:12:09+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force", "crypto"]
type: "posts"
showDate: true
---

For this challenge, we were given two pcapng files, `comm1.pcapng` and `comm2.pcapng`, and a text file. The text file contains this:


> Bonjour Agent-CTF,
> 
> Nous avons recemment interceptés un message, chiffré grace a un algorithme inconnu.
> Nous avons mis en relation ce message a un message anterieur, contenant une discussion suspecte entre deux membres de l'APT.
> 
> Votre mission sera de dechiffrer les communications.
> 
> Bonne chance
> 
> Q.G.

We can use tshark to view the raw data of the network captures:

```cli
$ tshark -r comm1.pcapng -T fields -e data | xxd -r -p
Hey, could you generate an rsa key for me ? I Dont know how to do it
Yes sure, i just need a prime integer to generate it
Just take a random one, like 347 for example
Perfect, i'll keep you in touch

$ tshark -r comm2.pcapng -T fields -e data | xxd -r -p
Hello
-----BEGIN PUBLIC KEY-----
MBwwDQYJKoZIhvcNAQEBBQADCwAwCAIDBGOvAgER            
-----END PUBLIC KEY-----
71436 176304 185211 110406 35389 179680 56238 185211 207993 237729 176304 207993 185211 192576 237729 95070 171155 207993 35389 185211 110406 140230 92028 110406 140230 246626 82805
95994 185211 110406 176304 192576 230623 185211 110406 237729 171155 110406 247756 185211 192576 230623 185211 110406 237729 176304 140230 92028 110406 232955 247756 192576 35389 185211 82805
194813 185211 207993 185211 110406 140230 92028 110406 237729 176304 185211 110406 92028 185211 35389 207993 185211 237729 110406 35389 171155 171098 185211 110406 105244 110406 228171 207520 180458 196399 104282 71436 31634 106170 103296 132591 35389 69499 171098 196399 24720 104282 92028 59381 24720 230238 230238 36350
````

The first message tells us about a message encrypted using RSA, for which a factor is 347. The second message contains the public key, and the message itself (the value of each char).

We can be lazy and use [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) to get ourselves the private key parameters, after copying the public key to a file.

```bash
$ python RsaCtfTool.py --publickey key.pub --private --dumpkey
[*] Testing key key.pub.
[*] Performing mersenne_primes attack on key.pub.
[*] Performing smallq attack on key.pub.
[*] Attack success with smallq method !

Results for key.pub:

Private key :
-----BEGIN RSA PRIVATE KEY-----
MCQCAQACAwRjrwIBEQIDAQdRAgIDPQICAVsCAgFVAgIBHQICAxI=
-----END RSA PRIVATE KEY-----
n: 287663
e: 17
d: 67409
p: 829
q: 347

Public key details for key.pub                                                                                        
n: 287663
e: 17
````

Now all we have to do is map each number to the power of `d`, mod `n` ([ref](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Decryption)):

```python
d = 67409
n = 287663

lines = '''
71436 176304 185211 110406 35389 179680 56238 185211 207993 237729 176304 207993 185211 192576 237729 95070 171155 207993 35389 185211 110406 140230 92028 110406 140230 246626 82805
95994 185211 110406 176304 192576 230623 185211 110406 237729 171155 110406 247756 185211 192576 230623 185211 110406 237729 176304 140230 92028 110406 232955 247756 192576 35389 185211 82805
194813 185211 207993 185211 110406 140230 92028 110406 237729 176304 185211 110406 92028 185211 35389 207993 185211 237729 110406 35389 171155 171098 185211 110406 105244 110406 228171 207520 180458 196399 104282 71436 31634 106170 103296 132591 35389 69499 171098 196399 24720 104282 92028 59381 24720 230238 230238 36350
'''.strip()

for line in lines.split('\n'):
	blocks = list(map(int, line.split()))
	print(''.join([chr((block ** d) % n) for block in blocks]))
```
```bash
$ python solve.py
The cyberthreatforce is in.
We have to leave this place.
Here is the secret code : CYBERTF{D3c0dE_Rs4_!!}
```

The flag is `CYBERTF{D3c0dE_Rs4_!!}`.

Note: even though I was the one to input the flag in CTFd, it was my teammate [R0ck3t](https://ctftime.org/user/46515) that found it first.

You can [view the sources on github](https://github.com/vivescere/ctf/tree/main/cyber-threat-force-2021/crypto/unefficient-encryption) or [read other writeups](/blog/cyber-threat-force-ctf/).
