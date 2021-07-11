---
title: "Writeup Cyber Threat Force : Viking crypt"
date: 2021-07-11T05:07:09+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force", "reverse"]
type: "posts"
showDate: true
---

For this challenge, we were given a ransomware (`VIKING_CRYPT.exe` and `VIKING_DECRYPT.exe`) along with a `LOCKER.HTML` file and `IMPORTANT_NOTE.txt.vkg`.

![Viking locker ransom message](/assets/cyber-threat-force/viking-locker.png)

Let's take a look at that encrypted note:

```bash
$ file Perso/IMPORTANT_NOTE.txt.vkg
Perso/IMPORTANT_NOTE.txt.vkg: ASCII text, with no line terminators
$ cat Perso/IMPORTANT_NOTE.txt.vkg
8a9b600b5a745d39cb7c7e7890e816848a9fe77280b42ca0751d150bb849
````

It doesn't really look like any encryption I know.

We can try to run `VIKING_DECRYPT.exe`:

{{< image src="/assets/cyber-threat-force/viking-locker-decrypt.png" alt="Viking locker decrypt executable" position="center">}}

As expected, we're asked for a decryption key. Let's encrypt a few files in a VM, and compare the plaintext and the `.vkg` files.

Note: the challenge description tells us that, for safety, the malware will only encrypt files in `C:\Users\nMnHkfcWUjE\Desktop\Perso`.

```bash
$ echo 'hello world' > normal.txt
$ echo 'h3110 w0r1d' > leet.txt
```

```ps
PS C:\Users\nMnHkfcWUjE\Desktop> .\VIKING_CRYPT.exe
```

```bash
$ cat normal.txt.vkg
a1a74e2267006c2df04f5e

$ cat leet.txt.vkg
a1f1137f38006c72f0125e
```

Now this is promising. The matching `h` has the same value. Let's try a simple xor between the plaintext and the encrypted value, to see if we get a matching key:

```python
>>> import codecs
>>> print([a ^ b for a, b in zip(b'hello world', codecs.decode('a1a74e2267006c2df04f5e', 'hex'))])
[201, 194, 34, 78, 8, 32, 27, 66, 130, 35, 58]
>>> print([a ^ b for a, b in zip(b'h3110 w0r1d', codecs.decode('a1f1137f38006c72f0125e', 'hex'))])
[201, 194, 34, 78, 8, 32, 27, 66, 130, 35, 58]
```

The key is exactly the same! Let's try decrypting our important note:

```python
>>> key = [a ^ b for a, b in zip(b'h3110 w0r1d', codecs.decode('a1f1137f38006c72f0125e', 'hex'))]
>>> print(bytes([a ^ b for a, b in zip(key, codecs.decode('8a9b600b5a745d39cb7c7e7890e816848a9fe77280b42ca0751d150bb849', 'hex'))]))
b'CYBERTF{I_D'
```

Well that's only the start of the flag. Let's encrypt something longer, to get more bytes of the key:

```bash
$ echo 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed non enim quam. Morbi luctus tortor dolor, sed pellentesque urna vestibulum eget. In egestas diam tempus risus molestie, id consectetur ante euismod. Integer eget erat sapien.' > long.txt
$ # Run VIKING_CRYPT.exe
$ cat long.txt.vkg
85ad502b65007232f15657689af325bbccc6cb4f9ca7129f24074a1bb65bc8c30162703e3f36149f38c754567af424eb60682eda379edab1b7fe5b44c4df29c471f802c8d8716192291c829b89c3c49695ec48abf2f3721e5b229a20afb2b7c751779c51ff63f378a7a53c27113b306c26fc2b87562768cc82b70cfdbd3fc93730f890234ac890c6e6b9e052f65341eaaf3f7e56d9476c170f17dd5e3830867656c0fd885a68a55ae58bcb182a09ee0a840a03511fb3222d25637b1d344340168dfebdd97a8bc327a36e6d9703f9e6427e9dfd07df86f0140a067a3a843aeef6f4782df2f1e56e380957c2
```

```python
>>> cleartext = b'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed non enim quam. Morbi luctus tortor dolor, sed pellentesque urna vestibulum eget. In egestas diam tempus risus molestie, id consectetur ante euismod. Integer eget erat sapien.'
>>> cipher = '85ad502b65007232f15657689af325bbccc6cb4f9ca7129f24074a1bb65bc8c30162703e3f36149f38c754567af424eb60682eda379edab1b7fe5b44c4df29c471f802c8d8716192291c829b89c3c49695ec48abf2f3721e5b229a20afb2b7c751779c51ff63f378a7a53c27113b306c26fc2b87562768cc82b70cfdbd3fc93730f890234ac890c6e6b9e052f65341eaaf3f7e56d9476c170f17dd5e3830867656c0fd885a68a55ae58bcb182a09ee0a840a03511fb3222d25637b1d344340168dfebdd97a8bc327a36e6d9703f9e6427e9dfd07df86f0140a067a3a843aeef6f4782df2f1e56e380957c2'
>>> key = [a ^ b for a, b in zip(cleartext, codecs.decode(cipher, 'hex'))]
>>> print(bytes([a ^ b for a, b in zip(key, codecs.decode('8a9b600b5a745d39cb7c7e7890e816848a9fe77280b42ca0751d150bb849', 'hex'))]))
b'CYBERTF{I_D0nt_P4y_Th3_R4ns0m}'
```

Here we go, the flag is `CYBERTF{I_D0nt_P4y_Th3_R4ns0m}`.

By the way, the key doesn't seem to repeat (at least for the first 235 values), so it's probably made from a RNG.

You can [view the sources on github](https://github.com/vivescere/ctf/tree/main/cyber-threat-force-2021/reverse/viking-crypt) or [read other writeups](/blog/cyber-threat-force-ctf/).
