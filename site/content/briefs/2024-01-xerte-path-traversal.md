---
title: Xerte Online Toolkits Path Traversal Vulnerability
slug: 2024-01-xerte-path-traversal
description: Xerte Online Toolkits 3.15 and earlier are vulnerable to relative path traversal, allowing attackers to move files and potentially achieve remote code execution.
date: "2024-01-03T12:00:00Z"
severities:
  - critical
tags:
  - path-traversal
  - remote-code-execution
  - xss
vendors:
  - Xerte
products:
  - Xerte Online Toolkits (<= 3.15)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1552
    technique_name: Unprotected Credentials
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unprotected Credentials
cves:
  - id: CVE-2026-34414
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34414
rules:
  - title: Detect Suspicious Path Traversal in Xerte Connector
    description: Detects attempts to exploit the path traversal vulnerability in the Xerte Online Toolkits elFinder connector by monitoring requests with directory traversal sequences in the 'name' parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect PHP Execution from Web Root
    description: Detects execution of PHP files from the web root directory, which may indicate exploitation of a path traversal vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.008
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Xerte Online Toolkits, a tool used to create online learning materials, is vulnerable to a path traversal vulnerability (CVE-2026-34414) in versions 3.15 and earlier. The vulnerability exists in the elFinder connector endpoint at `/editor/elfinder/php/connector.php`. The `name` parameter within rename commands is not properly sanitized, allowing attackers to use directory traversal sequences (e.g., `../`) to manipulate file locations. This flaw can be exploited to overwrite application files…
