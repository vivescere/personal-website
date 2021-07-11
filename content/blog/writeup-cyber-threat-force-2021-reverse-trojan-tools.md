---
title: "Writeup Cyber Threat Force : Trojan tools"
date: 2021-07-11T06:57:09+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force", "reverse"]
type: "posts"
showDate: true
---

For this challenge, we were given a `TROJAN_TOOLS.exe` file. Before manually analyzing it, I tried feeding it to [hybrid analysis](https://www.hybrid-analysis.com/).

Here is the link to [the full report](https://www.hybrid-analysis.com/sample/fe5b78b039a6800a2ae00db12559e971cc0a02caa72e29826d3e51ce88eb153b/60e02fcf19a4185d8f58ead3).

The "Interesting strings" section contained the flag: `CYBERTF{Y0u_H4s_P3wn_Th3_H4ck_T0ol}`.

---

We can also try to solve the challenge in a more conventional way. Executing the application gives us:


```ps
C:\Users\IEUser\Desktop>original.exe
Please enter the good PIN
```

## Using a process monitor

We can use [procmon](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon) from the Sysinternals suite to monitor the process.

{{< image src="/assets/cyber-threat-force/reverse-trojan-tools.png" alt="Procmon monitoring for the executable showing a WriteFile call" position="center">}}

We can see that a file is created and written to. It is deleted once the executable is done running, but there probably is a call to `Sleep` because we can open it in notepad if we're fast enough.

Here is is, containing the flag:

```powershell
Param($choix)

if($choix -eq 5383)
{
    Write-Host "Welcome to HackTool `r`n`r`n`r`n===MENU===`r`n1)FUD PAYLOAD`r`n2)DDOS`r`n3)Personnal note"

    $userChoice = Read-Host "Enter your choice : "

    if($userChoice -eq 1)
    {
        $trojanPath = Read-Host "Enter path of payload : "
        Write-Host "Obfuscating in progress..."
        Write-Host "The payload $trojanPath is now obufscated !"
        Write-Error "CRITICAL ERROR, IMPOSSIBLE TO OBFUSCATING PAYLOAD"
    }

    ElseIf ($userChoice -eq 2)
    {
        $ipToAttack = Read-Host "Enter IP to Ddos : "
        $portToAttack = Read-Host "Enter port of target : "
        Write-Host "ATTACK STARTED to $ipToAttack : $portToAttack"
        Write-Host "500 requests sended..."
        Write-Error "CRITICAL ERROR, IMPOSSIBLE TO SEND PACKET"
    }

    ElseIF ($userChoice -eq 3)
    {
        Write-Error "ERROR, OPTION 3 IS NOT INCORPORED PLEASE TRY 1 BETWEEN 10"
    }

    ElseIF ($userChoice -eq 8)
    {
        Write-Host "CYBERTF{Y0u_H4s_P3wn_Th3_H4ck_T0ol}"
    }

    Else
    {
        Write-Error "ERROR, OPTION $userChoice IS NOT INCORPORED PLEASE TRY 1 BETWEEN 10"
    }
}

else
{
    Write-Host "Please enter the good PIN"
}
```


## Unpacking the executable
    
I also noticed that the application was packed using [UPX](https://upx.github.io/), and that when unpacked, it
 contained the string `inflate 1.2.8 Copyright 1995-2013 Mark Adler`. This probably indicates nested zlib data. I couldn't find a way to extract anything else though: binwalk gives files that are almost fully filled with null bytes. And [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) doesn't help either.

## More

You can [view the sources on github](https://github.com/vivescere/ctf/tree/main/cyber-threat-force-2021/reverse/trojan-tools) or [read other writeups](/blog/cyber-threat-force-ctf/).
