---
title: Xerte Online Toolkits Unauthenticated Remote Code Execution via elFinder Connector
slug: 2024-01-xerte-rce
description: Xerte Online Toolkits versions 3.15 and earlier are vulnerable to unauthenticated remote code execution due to a missing authentication check in the elFinder connector, allowing arbitrary file operations that can be chained with other vulnerabilities.
date: "2024-01-24T12:00:00Z"
severities:
  - critical
tags:
  - CVE-2026-34413
  - xerte
  - rce
vendors:
  - Xerte
products:
  - Xerte Online Toolkits (3.15 and earlier)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34413
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34413
rules:
  - title: Detect Unauthenticated elFinder Connector Access
    description: Detects unauthorized access attempts to the elFinder connector in Xerte Online Toolkits, indicating potential exploitation of CVE-2026-34413.
    platform: sigma
    severity: critical
    tactics:
      - cve-2026-34413
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious File Uploads to elFinder Connector
    description: Detects potentially malicious file uploads via the elFinder connector in Xerte Online Toolkits by monitoring for specific HTTP parameters.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-34413
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Xerte Online Toolkits, a web-based open-source e-learning content creation platform, is vulnerable to a critical remote code execution vulnerability (CVE-2026-34413) affecting versions 3.15 and earlier. The vulnerability lies within the elFinder connector endpoint at `/editor/elfinder/php/connector.php`, which lacks proper authentication. This allows unauthenticated attackers to bypass intended access controls and directly interact with the file management system. Attackers can leverage this…
