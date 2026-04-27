---
title: KodExplorer Path Traversal Vulnerability (CVE-2026-6568)
slug: 2026-04-kodexplorer-path-traversal
description: KodExplorer up to version 4.52 is vulnerable to a path traversal attack via manipulation of the path argument in the share.class.php::initShareOld function, potentially allowing remote attackers to access sensitive files.
date: "2026-04-19T10:16:09Z"
severities:
  - high
exploited: true
tags:
  - path-traversal
  - kodexplorer
  - cve-2026-6568
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6568
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6568
  - https://vuldb.com/submit/789981
  - https://vuldb.com/vuln/358202
  - https://vuldb.com/vuln/358202/cti
  - https://vulnplus-note.wetolink.com/share/JyHBnRUaoOY2
ioc_counts:
  email: 1
  url: 4
rules:
  - title: Detect KodExplorer Path Traversal Attempt
    description: Detects path traversal attempts targeting the KodExplorer share.class.php endpoint
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Double Encoding Path Traversal in KodExplorer
    description: Detects path traversal attempts using double URL encoding in KodExplorer requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A path traversal vulnerability, identified as CVE-2026-6568, affects kodcloud KodExplorer up to version 4.52. The vulnerability resides within the `share.class.php::initShareOld` function in the `/app/controller/share.class.php` file, a part of the Public Share Handler component. An attacker can exploit this flaw by manipulating the `path` argument, leading to unauthorized access to files and directories outside of the intended share path. Public exploit code is available, increasing the risk…
