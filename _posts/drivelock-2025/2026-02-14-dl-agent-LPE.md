---
layout: post_collection_entry
date:   2026-02-14
categories: [advisory]
advisory_collection: drivelock_multi_2026

title:  "[Advisory - DriveLock] DriveLock Agent - Arbitrary file write allows LPE"
advisory:
  product: DriveLock
  homepage: https://www.drivelock.com/
  vulnerable_version: "25.1.4.58314"
  fixed_version: " 24.2.8, 25.1.6"
  found: 2025-09-28
  cve: "CVE-2025-67794"
  impact_text: HIGH
  impact_score: 7.5
  cvss: CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H
---

# Product description
> The HYPERSECURE Endpoint Protection Platform ensures that attacks on IT systems are kept where they belong: outside.
> This means you are secure at the centre, with all paths of access to your sensitive data blocked.

*Cite: [DriveLock - Homepage](https://www.drivelock.com/en/)*

This platform includes the `DriveLock Core` component, which is an agent installed on the client machines.

## Tested version
```ps1
PS C:\Users\pentest> Get-FileHash "C:\Program Files\CenterTools\DriveLock\DriveLock.exe"

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          D80D25A33FE3C39C72C7204C6E4AC780A51F8259BD38B9E2A7E85000C7DA66A9       C:\Program Files\CenterTools\DriveLock\DriveLock.exe

PS C:\Users\pentest> Get-ItemProperty "C:\Program Files\CenterTools\DriveLock\DriveLock.exe" |fl -Property versioninfo


VersionInfo : File:             C:\Program Files\CenterTools\DriveLock\DriveLock.exe
              InternalName:     DriveLock.exe
              OriginalFilename: DriveLock.exe
              FileVersion:      25.1.4.58314
              FileDescription:  Agent service
              Product:          DriveLock
              ProductVersion:   25.1.4.58314
              Debug:            False
              Patched:          False
              PreRelease:       False
              PrivateBuild:     False
              SpecialBuild:     False
              Language:         English (United States)
```

# Vulnerabilities overview
## 1) DriveLock service - Heap buffer overflow
...
## 2) Log folder permissions - RW Everyone
...

References how to exploit this setup:
* [Troopers 19 - Absuing privileged file operations,  18th – 22nd March 2019](https://troopers.de/downloads/troopers19/TROOPERS19_AD_Abusing_privileged_file_operations.pdf)
* [Synactive - Windows 10 PlugScheduler elevation of privilege](https://www.synacktiv.com/en/advisories/windows-10-plugscheduler-elevation-of-privilege)

# Proof of Concept
...

## Details
...

## Demonstration
...