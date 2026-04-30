---
title: File Browser Share Links Accessible After Permission Revocation
slug: 2026-04-filebrowser-share-bypass
description: File Browser share links remain accessible after Share/Download permissions are revoked, allowing continued access to shared files even after an administrator revokes the user's permissions.
date: "2026-04-08T00:04:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - filebrowser
  - authorization-bypass
  - github-advisory
  - cve-2026-35604
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-35604
references:
  - https://github.com/advisories/GHSA-v9w4-gm2x-6rvf
rules:
  - title: File Browser Public Share Download After Permission Revocation
    description: Detects attempts to download files via public share links after the share owner's permissions have been revoked.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: File Browser User Permission Modification
    description: Detects API calls to modify user permissions, which may precede attempts to exploit the share bypass vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: File Browser Share Creation Attempt After Permission Revocation
    description: Detects attempts to create shares after the user has had share permissions revoked, which should result in a 403 error.
    platform: sigma
    severity: informational
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 3
---

File Browser versions prior to 2.63.1 contain an authorization bypass vulnerability. Specifically, when an administrator revokes a user's share and download permissions, existing share links created by that user remain fully accessible to unauthenticated users. The vulnerability exists because the public share download handler (`http/public.go`) does not re-check the share owner's current permissions when serving shared files. This can lead to unauthorized data access and a false sense of security for administrators who believe that revoking permissions immediately terminates access to shared resources. The issue was verified against version 2.62.2 (commit 860c19d).

## Attack Chain

1. An administrator creates a user account with Share and Download permissions.
2. The user logs in and creates a share link for a file (e.g., `secret.txt`). The system generates a hash (e.g., `fB4Qwtsn`) associated with the share.
3. An unauthenticated user accesses the file via the share link (e.g., `/api/public/dl/fB4Qwtsn`), successfully downloading the content.
4. The administrator revokes the user's Share and Download permissions via the API, modifying the user's record in the system.
5. The revoked user attempts to create a new share link and is correctly denied access (403 Forbidden).
6. An unauthenticated user attempts to access the file using the previously created share link (e.g., `/api/public/dl/fB4Qwtsn`).
7. The system retrieves the share link information but fails to validate if the original user still possesses Share and Download permissions.
8. The system serves the file, bypassing the intended authorization restrictions and granting unauthorized access.

## Impact

The vulnerability allows unauthorized access to files shared through File Browser, even after an administrator has revoked the share creator's permissions. This can result in data breaches, as users who should no longer have access to shared resources can still retrieve them via existing share links. The administrator may believe that revoking permissions immediately stops all sharing, leading to a false sense of security. This is particularly impactful in environments where sensitive data is shared via File Browser and access control is critical.

## Recommendation

*   Upgrade File Browser to version 2.63.1 or later to patch CVE-2026-35604.
*   Monitor web server logs for access to `/api/public/dl/*` endpoints (logsource: webserver, product: linux/windows) after revoking user permissions; correlate with user permission changes.
*   Implement the suggested fix by adding permission re-validation in `withHashFile` as described in the advisory.
