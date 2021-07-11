---
title: "Writeup Cyber Threat Force : Azkaban C2"
date: 2021-07-11T09:45:09+01:00
draft: false
tags: ["blog", "security", "ctf", "cyber-threat-force", "misc"]
type: "posts"
showDate: true
---

For this challenge, we were given a python script:

```python
import socket

def menu():
    print("______________________")
    print("|       MENU         |")
    print("| 1) see option      |")
    print("| 2) edit option     |")
    print("| 3) connect         |")
    print("______________________")
    
print("""

  ______             __                  __                                             ______  
 /      \           /  |                /  |                                           /      \ 
/$$$$$$  | ________ $$ |   __   ______  $$ |____    ______   _______          _______ /$$$$$$  |
$$ |__$$ |/        |$$ |  /  | /      \ $$      \  /      \ /       \        /       |$$____$$ |
$$    $$ |$$$$$$$$/ $$ |_/$$/  $$$$$$  |$$$$$$$  | $$$$$$  |$$$$$$$  |      /$$$$$$$/  /    $$/ 
$$$$$$$$ |  /  $$/  $$   $$<   /    $$ |$$ |  $$ | /    $$ |$$ |  $$ |      $$ |      /$$$$$$/  
$$ |  $$ | /$$$$/__ $$$$$$  \ /$$$$$$$ |$$ |__$$ |/$$$$$$$ |$$ |  $$ |      $$ \_____ $$ |_____ 
$$ |  $$ |/$$      |$$ | $$  |$$    $$ |$$    $$/ $$    $$ |$$ |  $$ |      $$       |$$       |
$$/   $$/ $$$$$$$$/ $$/   $$/  $$$$$$$/ $$$$$$$/   $$$$$$$/ $$/   $$/        $$$$$$$/ $$$$$$$$/ 
                                                                                                
-----=[Azkaban C2 v.0.0.1 alpha]
""")

def see_option():
    print("_________________________________")
    print("| PIN CODE : " + pin_code + "               |")
    print("| Team Serveur IP : " + teamserver_ip + "|")
    print("| Team Serveur Port : " + teamserver_port + "      |")
    print("_________________________________")
        
def edit_option():
    print("Current option :")
    see_option()
    print("Where option you want to edit ?")
    
    print(" 1) PIN_CODE\n2) TeamServer IP \n3) TeamServer Port ")
    choix = input("Azk-c2 > ")
    choix = str(choix)
    while (True):
        if choix == "1":
            pin_code = input("Azk-c2 | Edit PIN_CODE > ")
            pin_code = str(pin_code)
            print("[+]PIN_CODE : " + pin_code)
            break
            
        elif choix == "2":
            teamserver_ip  = input("Azk-c2 | Edit TeamServer IP > ")
            teamserver_ip = str(teamserver_ip)
            print("[+]TeamServer IP : " + teamserver_ip)
            break
            
        elif choix == "3":
            teamserver_port  = input("Azk-c2 | Edit TeamServer Port > ")
            teamserver_port = str(teamserver_port)
            print("[+]TeamServer Port : " + teamserver_port)
            break
        else:
            print("Error")
    
def connect(pin_code, teamserver_ip, teamserver_port):

    teamserver_port = int(teamserver_port)
    
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
    clientSocket.connect((teamserver_ip,teamserver_port));
    clientSocket.send(pin_code.encode());
    dataFromServer = clientSocket.recv(1024);
    print(dataFromServer.decode());
    
    res = input("Azk-c2 > ")
    res = str(res)
    clientSocket.send(res.encode());
    dataFromServer = clientSocket.recv(1024);
    print(dataFromServer.decode());
    
    

while (True):
    menu()
    pin_code = "4785"
    teamserver_ip = "144.217.73.235"
    teamserver_port = "26007"
    
    
    choix = input("Azk-c2 > ")
    choix = str(choix)
    if choix == "1":
        see_option()
    elif choix == "2":
        edit_option()
    elif choix == "3":
        connect(pin_code, teamserver_ip, teamserver_port)
    else:
        print("Bad choice, try again")
```


At the end, we can see an IP, a port, and a PIN. Upon connecting to the service using netcat, it asked us the result of a simple addition. After that, we had to enter the pin (4785), and select an option. Option 2, "Dump creds", printed out the flag.

I unfortunately am writting this after the server was shutdown, so I can't include a demo.

The flag is `CYBERTF{0wn_th3_t3ams3rv3r}`.

You can [view the sources on github](https://github.com/vivescere/ctf/tree/main/cyber-threat-force-2021/misc/azkaban-c2) or [read other writeups](/blog/cyber-threat-force-ctf/).
