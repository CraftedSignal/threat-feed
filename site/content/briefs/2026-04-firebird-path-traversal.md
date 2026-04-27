---
title: Firebird Path Traversal Vulnerability Leads to Code Execution (CVE-2026-40342)
slug: 2026-04-firebird-path-traversal
description: An authenticated user with CREATE FUNCTION privileges can exploit a path traversal vulnerability in Firebird versions prior to 5.0.4, 4.0.7, and 3.0.14, to load an arbitrary shared library leading to code execution as the server's OS account.
date: "2026-04-17T20:16:35Z"
severities:
  - critical
tags:
  - firebird
  - path-traversal
  - code-execution
  - cve-2026-40342
  - database
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1202
    technique_name: Indirect Command Execution
cves:
  - id: CVE-2026-40342
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40342
rules:
  - title: Detect Firebird Create Function Path Traversal
    description: Detects CREATE FUNCTION statements in Firebird with ENGINE names containing path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1202
    data_sources:
      - database
      - firebird
  - title: Detect Shared Library Load from Suspicious Path
    description: Detects loading of shared libraries from /tmp or other suspicious paths, which may indicate exploitation of CVE-2026-40342
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Firebird, an open-source relational database management system, is vulnerable to a path traversal flaw (CVE-2026-40342) in versions prior to 5.0.4, 4.0.7, and 3.0.14. This vulnerability resides within the external engine plugin loader. The loader concatenates a user-supplied engine name into a filesystem path without proper sanitization, leaving it open to path traversal attacks. An authenticated user with `CREATE FUNCTION` privileges can craft a malicious `ENGINE` name containing path…
