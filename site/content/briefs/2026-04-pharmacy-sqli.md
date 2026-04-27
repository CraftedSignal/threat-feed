---
title: SourceCodester Pharmacy Sales and Inventory System SQL Injection
slug: 2026-04-pharmacy-sqli
description: SourceCodester Pharmacy Sales and Inventory System 1.0 is vulnerable to SQL injection via the Username parameter in the /ajax.php?action=login endpoint, potentially allowing remote attackers to execute arbitrary SQL commands.
date: "2026-04-13T17:16:31Z"
severities:
  - high
tags:
  - sqli
  - vulnerability
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6189
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6189
rules:
  - title: Detect SQL Injection Attempt in Pharmacy System Login
    description: Detects potential SQL injection attempts targeting the /ajax.php?action=login endpoint by looking for common SQL keywords in the Username parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Malicious SQL Error Messages
    description: Detects SQL error messages that can indicate a possible SQL injection attack in Pharmacy System
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

SourceCodester Pharmacy Sales and Inventory System 1.0 is susceptible to a SQL injection vulnerability (CVE-2026-6189). Disclosed publicly, the flaw resides within the `/ajax.php?action=login` endpoint and can be triggered by manipulating the `Username` parameter. Remote attackers can exploit this vulnerability to potentially execute arbitrary SQL commands, leading to unauthorized data access, modification, or deletion. This vulnerability poses a significant risk to organizations using the…
