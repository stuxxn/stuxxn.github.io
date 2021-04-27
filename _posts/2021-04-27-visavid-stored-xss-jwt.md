---
layout: post
date:   2021-04-27
categories: [advisory]

title:  "Advisory - Visavid account hijack via stored XSS "
advisory:
  product: Visavid
  homepage: https://visavid.de/
  
  vulnerable_version: ["Gateway 1.10.3", "Verwaltung: 1.10.10"]
  fixed_version: ["Gateway 1.10.3", "Verwaltung: 1.10.14"]
  impact_text: HIGH
  impact_score: 8.0
  cvss: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H
  found: 2021-04-22
---

# Product description
Kommunizieren, präsentieren, fortbilden: Unsere flexible Videokonferenz-Software ist von der Entwicklung bis zum Support zu 100 % Made in Germany und bietet neben Datenschutz und einem hohen Sicherheits-Level auch individuelle Anpassungsmöglichkeiten für unterschiedliche Einsatzbereiche.

[Auctores - Visavid](https://auctores.de/software/produkte/)

# Vulnerability overview
The software `Visavid` allows an `room` admin to upload files for the room. These uploaded files can then be accessed without authentication. As the content type/data of the uploaded file is not restricted, a `HTML` file with included `JavaScript` code can be uploaded.  If the victim visits the URL the `JWT` can be accessed from the `localStorage` and sent back to the attacker, which allows full access to the account.

# Proof of concept
The endpoint `PUT /api/verwaltung/rooms/file/{ROOM-ID}` allows an user to upload files to a room. As the content type/data is not restricted a `HTML` file with malicious `JavaScript` code can be uploaded. The result to this requests contains the resource URL (`file.data.url`), which can be used to access the file without authentication. This URL can then be sent to a victim. If the victim opens the URL and is logged in the `JWT` can be stolen.

The request to upload a HTML file:
```http
PUT /api/verwaltung/rooms/file/6f735b70-27ee-41dc-a1df-778446f40fcc HTTP/1.1
Host: staging.visavid.de
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: application/hal+json
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Authorization: Bearer XXX
Content-Type: multipart/form-data; boundary=---------------------------266190233231735721582577257025
Content-Length: 2567
Origin: https://staging.visavid.de
DNT: 1
Connection: close

-----------------------------266190233231735721582577257025
Content-Disposition: form-data; name="id"

6f735b70-27ee-41dc-a1df-778446f40fcc
-----------------------------266190233231735721582577257025
Content-Disposition: form-data; name="file_file"; filename="extract-jwt.html"
Content-Type: text/html

<!DOCTYPE html>
<html lang="en">
<meta charset="UTF-8">
<title>Visavid - Stored XSS</title>

........

</html>
-----------------------------266190233231735721582577257025
Content-Disposition: form-data; name="view_initial"

false
-----------------------------266190233231735721582577257025
Content-Disposition: form-data; name="room_id"

{"id":"{ROOM-ID}"}
-----------------------------266190233231735721582577257025--

```
The response contains the resource URL, which is available without login:
```json
{
    "file": {
        "data": {
            "id": "141f4e8fX178b54d7629XY7fa1",
            "url": "resources/466524208/141f4e8fX178b54d7629XY7fa1/ORG/extract-jwt.html",
            "name": "extract-jwt.html",
            "size": 1910,
            "alias": "default",
            "index": "visavid",
            "format": "ORG",
            "public": false,
            "imgWidth": 0,
            "mimeType": "text/html",
            "extension": "html",
            "imgHeight": 0,
            "timestamp": 1619090844873,
            "indexHashed": "466524208",
            "imgColorSpace": 0,
            "entityId": "6f735b70-27ee-41dc-a1df-778446f40fcc",
            "entityPath": "/rooms/file"
        },
        "url": "/api/verwaltung/rooms/file/6f735b70-27ee-41dc-a1df-778446f40fcc/blobs/3143036/{FORMAT}/extract-jwt.html"
    },
    "view_initial": false,
    "defaultvalue": "extract-jwt.html",
    "id": "6f735b70-27ee-41dc-a1df-778446f40fcc"
}
```

If the victim open the resource URL `https://staging.visavid.de/resources/466524208/141f4e8fX178b54d7629XY7fa1/ORG/extract-jwt.html` the `JavaScript` code is executed.

```http
GET /resources/466524208/141f4e8fX178b54d7629XY7fa1/ORG/extract-jwt.html HTTP/1.1
Host: staging.visavid.de
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Pragma: no-cache
Cache-Control: no-cache


```

To demonstrate  the impact a small `JWT` stealing PoC was created (full source in appendix).
If the victim is already logged in the current `JWT` is sent back to the attacker. 
![already logged in](/assets/visavid/210422-stored-xss-logged-in.png)

Otherwise the normal login prompt is shown and the stealing function is called every two second until the user is logged in and the token is sent back.
![not logged in](/assets/visavid/210422-stored-xss-login-page.png)  

After the user logged in:
![after login](/assets/visavid/210422-stored-xss-after-login.png)

# Timeline
* 2021-04-22: Sent report to vendor
* 2021-04-23: Vendor acknowledged vulnerability
* 2021-04-26: Vendor informed that the issue is fixed
* 2021-04-27: Public release of security advisory


# Reference
* [OWASP - JSON Web Token](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-storage-on-client-side)
* [OWASP - Cross Site Scripting](https://owasp.org/www-community/attacks/xss/)
* [Medium - Whats the secure way to store JWT](https://medium.com/swlh/whats-the-secure-way-to-store-jwt-dd362f5b7914)


# Appendix
```html
{% include poc/visavid-extract-jwt.html %}
```
