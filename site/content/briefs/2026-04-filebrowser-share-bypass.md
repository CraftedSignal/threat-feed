---
title: File Browser Share Links Accessible After Permission Revocation
slug: 2026-04-filebrowser-share-bypass
description: File Browser share links remain accessible after Share/Download permissions are revoked, allowing continued access to shared files even after an administrator revokes the user's permissions.
date: "2026-04-08T00:04:59Z"
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

File Browser versions prior to 2.63.1 contain an authorization bypass vulnerability. Specifically, when an administrator revokes a user's share and download permissions, existing share links created by that user remain fully accessible to unauthenticated users. The vulnerability exists because the public share download handler (`http/public.go`) does not re-check the share owner's current permissions when serving shared files. This can lead to unauthorized data access and a false sense of…
