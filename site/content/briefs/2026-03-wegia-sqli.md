---
title: WeGIA Web Manager SQL Injection Vulnerability (CVE-2026-33991)
slug: 2026-03-wegia-sqli
description: WeGIA web manager prior to version 3.6.7 is vulnerable to SQL injection via the `id_tag` parameter in the `deletar_tag.php` script due to unsanitized input and direct concatenation into SQL queries, potentially allowing attackers to read, modify, or delete data.
date: "2026-03-27T23:17:13Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-33991
  - sql-injection
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33991
  - https://github.com/LabRedesCefetRJ/WeGIA/security/advisories/GHSA-74xm-6wgf-x37j
rules:
  - title: Detect WeGIA SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the WeGIA application by looking for suspicious keywords in HTTP request URIs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WeGIA SQL Injection via Extract Function Abuse
    description: Detects SQL injection attempts in WeGIA by identifying requests to the vulnerable deletar_tag.php script that also contain common SQL injection payloads within request parameters.
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

WeGIA, a web manager for charitable institutions, is susceptible to SQL injection in versions prior to 3.6.7. The vulnerability resides in the `html/socio/sistema/deletar_tag.php` file, where the application uses `extract($_REQUEST)` on line 14 and directly concatenates the `$id_tag` variable into SQL queries on lines 16-17. This occurs without proper sanitization or the use of prepared statements. The lack of input validation allows attackers to inject arbitrary SQL commands, potentially…
