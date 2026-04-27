---
title: SourceCodester Pharmacy Sales and Inventory System SQL Injection Vulnerability
slug: 2026-04-pharmacy-sales-sqli
description: SourceCodester Pharmacy Sales and Inventory System 1.0 is vulnerable to SQL injection by manipulating the ID argument in the /ajax.php?action=save_receiving file, allowing remote attackers to execute arbitrary SQL commands.
date: "2026-04-27T06:16:03Z"
severities:
  - high
tags:
  - sqli
  - web-application
  - cve-2026-7088
vendors:
  - SourceCodester
products:
  - Pharmacy Sales and Inventory System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7088
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7088
  - https://github.com/nidieaaa/test/issues/3
  - https://vuldb.com/vuln/359663
rules:
  - title: Detecting SQL Injection Attempts via URI
    description: Detects potential SQL injection attempts in the URI of HTTP requests based on common SQL injection payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detecting SQL Injection Error Messages
    description: Detects SQL injection attempts by identifying common database error messages in web server responses.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

SourceCodester Pharmacy Sales and Inventory System version 1.0 is susceptible to SQL injection. The vulnerability resides in the `/ajax.php?action=save_receiving` file, where manipulation of the `ID` argument can lead to arbitrary SQL command execution. This vulnerability allows remote attackers to compromise the application's database. The exploit is publicly available, increasing the risk of exploitation. This vulnerability allows attackers to read, modify, or delete sensitive data…
