---
title: UniFi Play Path Traversal Vulnerability (CVE-2026-22562)
slug: 2026-04-unifi-path-traversal
description: A path traversal vulnerability in UniFi Play devices allows an attacker with network access to write arbitrary files, leading to remote code execution.
date: "2026-04-14T14:00:00Z"
severities:
  - critical
tags:
  - path-traversal
  - rce
  - unifi
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
cves:
  - id: CVE-2026-22562
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22562
  - https://community.ui.com/releases/Security-Advisory-Bulletin-063/e468dd4b-5090-4ef8-89d8-939903c08e83
rules:
  - title: Path Traversal in URI
    description: Detects path traversal attempts in HTTP requests
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Suspicious File Creation in Common Web Directories
    description: Detects creation of executable files in web server directories which could be a sign of web shell deployment after a path traversal
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2026-22562 describes a critical path traversal vulnerability affecting UniFi Play PowerAmp (version 1.0.35 and earlier) and UniFi Play Audio Port (version 1.0.24 and earlier) devices. An attacker with access to the UniFi Play network can exploit this vulnerability to write arbitrary files on the file system. This capability can then be leveraged to achieve remote code execution (RCE) on the vulnerable device. Successful exploitation requires network access to the affected UniFi Play…
