---
title: "Writeup Cyber Threat Force : Smasher"
date: 2021-07-10T02:50:09+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force", "reverse"]
type: "posts"
showDate: true
---

For this challenge, we were given two files:
- `smasher-1.0.0.AppImage`
- `smasher_Setup_1.0.0.exe`

I only looked at the AppImage one, since I'm running linux. Launching the program reveals an electron app:

![The application](/assets/cyber-threat-force/smasher.png)

We can simply use the dev tools to reveal the source code. Only one javascript file is there, `login.js`:

```js
function Login() {
    var i = {
        _keyStr: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
        encode: function(r) {
            var t, e, o, a, n, c, h = "", d = 0;
            for (r = i._utf8_encode(r); d < r.length; )
                o = (c = r.charCodeAt(d++)) >> 2,
                a = (3 & c) << 4 | (t = r.charCodeAt(d++)) >> 4,
                n = (15 & t) << 2 | (e = r.charCodeAt(d++)) >> 6,
                c = 63 & e,
                isNaN(t) ? n = c = 64 : isNaN(e) && (c = 64),
                h = h + this._keyStr.charAt(o) + this._keyStr.charAt(a) + this._keyStr.charAt(n) + this._keyStr.charAt(c);
            return h
        },
        decode: function(r) {
            var t, e, o, a, n, c = "", h = 0;
            for (r = r.replace(/[^A-Za-z0-9\+\/\=]/g, ""); h < r.length; )
                t = this._keyStr.indexOf(r.charAt(h++)) << 2 | (o = this._keyStr.indexOf(r.charAt(h++))) >> 4,
                e = (15 & o) << 4 | (a = this._keyStr.indexOf(r.charAt(h++))) >> 2,
                o = (3 & a) << 6 | (n = this._keyStr.indexOf(r.charAt(h++))),
                c += String.fromCharCode(t),
                64 != a && (c += String.fromCharCode(e)),
                64 != n && (c += String.fromCharCode(o));
            return c = i._utf8_decode(c)
        },
        _utf8_encode: function(r) {
            r = r.replace(/\r\n/g, "\n");
            for (var t = "", e = 0; e < r.length; e++) {
                var o = r.charCodeAt(e);
                o < 128 ? t += String.fromCharCode(o) : (127 < o && o < 2048 ? t += String.fromCharCode(o >> 6 | 192) : (t += String.fromCharCode(o >> 12 | 224),
                t += String.fromCharCode(o >> 6 & 63 | 128)),
                t += String.fromCharCode(63 & o | 128))
            }
            return t
        },
        _utf8_decode: function(r) {
            for (var t = "", e = 0, o = c1 = c2 = 0; e < r.length; )
                (o = r.charCodeAt(e)) < 128 ? (t += String.fromCharCode(o),
                e++) : 191 < o && o < 224 ? (c2 = r.charCodeAt(e + 1),
                t += String.fromCharCode((31 & o) << 6 | 63 & c2),
                e += 2) : (c2 = r.charCodeAt(e + 1),
                c3 = r.charCodeAt(e + 2),
                t += String.fromCharCode((15 & o) << 12 | (63 & c2) << 6 | 63 & c3),
                e += 3);
            return t
        }
    }
      , r = document.login.password.value;
    "Q1lCRVJURntNMFIzX04zZzR0MXYzX3RoNG5fNF9wcjB0MG59" == i.encode(r) ? (alert("Welcome to admin panel"),
    location.replace("https://www.youtube.com/watch?v=dQw4w9WgXcQ")) : alert("wrong password")
}
```

That bottom string is compared with the password that we can enter, and looks like base64. Let's try to decode it:

```js
> atob('Q1lCRVJURntNMFIzX04zZzR0MXYzX3RoNG5fNF9wcjB0MG59')
"CYBERTF{M0R3_N3g4t1v3_th4n_4_pr0t0n}"
```

And so we have our flag: `CYBERTF{M0R3_N3g4t1v3_th4n_4_pr0t0n}`.

Note that I didn't flag this during the CTF, my teammate [R0ck3t](https://ctftime.org/user/46515) did.

You can [view the sources on github](https://github.com/vivescere/ctf/tree/main/cyber-threat-force-2021/reverse/smasher) or [read other writeups](/blog/cyber-threat-force-ctf/).
