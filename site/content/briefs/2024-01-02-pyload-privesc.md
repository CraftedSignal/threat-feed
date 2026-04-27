---
title: pyLoad Privilege Escalation Vulnerability (CVE-2026-41133)
slug: 2024-01-02-pyload-privesc
description: pyLoad versions up to 0.5.0b3.dev97 cache user roles and permissions in the session, leading to privilege escalation even after an admin revokes privileges.
date: "2026-04-22T00:16:29Z"
severities:
  - high
tags:
  - pyLoad
  - privilege-escalation
  - CVE-2026-41133
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-41133
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41133
rules:
  - title: Detect pyLoad Admin Role Change Followed by User Activity
    description: Detects a user performing actions after their role has been changed by an administrator, potentially indicating exploitation of CVE-2026-41133.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-41133
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect PyLoad Unauthorized API Access
    description: Detects access to sensitive API endpoints after a role change, indicating potential privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-41133
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

pyLoad, a free and open-source download manager written in Python, is vulnerable to a privilege escalation issue. Specifically, versions up to and including 0.5.0b3.dev97 cache user `role` and `permission` data within the session upon login. This cached data is then used to authorize subsequent requests, even if an administrator modifies the user's roles or permissions directly in the database. Consequently, a user who is already logged in retains their original, possibly revoked, privileges…
