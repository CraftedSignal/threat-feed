---
title: Goshs File-Based ACL Authorization Bypass Vulnerability
slug: 2026-04-goshs-acl-bypass
description: Goshs is vulnerable to an authorization bypass (CVE-2026-40189) due to inconsistent enforcement of .goshs ACLs on state-changing routes, allowing an unauthenticated attacker to manipulate files within protected directories and bypass authentication barriers.
date: "2026-04-10T20:02:46Z"
severities:
  - critical
tags:
  - authorization bypass
  - acl
  - file upload
  - file deletion
  - CVE-2026-40189
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1211
    technique_name: Exploitation of Web Applications
references:
  - https://github.com/advisories/GHSA-wvhv-qcqf-f3cx
ioc_counts:
  url: 4
rules:
  - title: Detect Goshs Unauthenticated .goshs Deletion
    description: Detects attempts to delete .goshs ACL files via the ?delete parameter, indicating a potential authorization bypass.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
  - title: Detect Goshs Unauthenticated PUT Request to Protected Directories
    description: Detects PUT requests to directories that should be protected by .goshs ACLs, indicating a potential authorization bypass.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Goshs Unauthenticated Directory Creation via mkdir
    description: Detects requests with the `?mkdir` parameter, indicating a potential authorization bypass.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
rules_count: 3
---

The Goshs web server is susceptible to a critical authorization bypass (CVE-2026-40189) affecting versions up to and including 1.1.4 and v2.0.0-beta.3. The vulnerability stems from inconsistent enforcement of file-based ACLs defined by `.goshs` files. While the application correctly enforces authorization for reading and listing files, state-changing routes such as PUT, POST /upload, ?mkdir, and ?delete do not perform the same authorization checks. This allows unauthenticated attackers to…
