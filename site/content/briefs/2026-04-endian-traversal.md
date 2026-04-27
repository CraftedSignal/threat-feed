---
title: Endian Firewall Arbitrary File Deletion via Path Traversal (CVE-2026-34790)
slug: 2026-04-endian-traversal
description: Endian Firewall versions 3.3.25 and prior allow authenticated users to delete arbitrary files due to a path traversal vulnerability in the `remove ARCHIVE` parameter of the `/cgi-bin/backup.cgi` script, leading to unauthorized file system modification.
date: "2026-04-02T15:16:42Z"
severities:
  - high
tags:
  - cve
  - path-traversal
  - file-deletion
  - web-application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials on Shared Network Drive
cves:
  - id: CVE-2026-34790
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34790
  - https://help.endian.com/hc/en-us/sections/360004371358-Community
  - https://www.vulncheck.com/advisories/endian-firewall-cgi-bin-backup-cgi-remove-archive-directory-traversal
ioc_counts:
  email: 1
rules:
  - title: Detect Endian Firewall Path Traversal Attempt
    description: Detects potential path traversal attempts in the remove ARCHIVE parameter of /cgi-bin/backup.cgi on Endian Firewall.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Endian Firewall Unlink Call with Traversal
    description: Detects system unlink calls when attacker attempts a path traversal attack.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1555
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Endian Firewall, a security-focused Linux distribution designed for gateway security, is vulnerable to a path traversal attack. Specifically, versions 3.3.25 and earlier are affected by CVE-2026-34790. An authenticated user, with low-level privileges, can exploit this vulnerability to delete arbitrary files on the system. The flaw resides in the `/cgi-bin/backup.cgi` script where the `remove ARCHIVE` parameter is not properly sanitized. This allows an attacker to inject directory traversal…
