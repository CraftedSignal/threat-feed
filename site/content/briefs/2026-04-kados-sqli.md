---
title: Kados R10 GreenBee SQL Injection Vulnerability (CVE-2019-25692)
slug: 2026-04-kados-sqli
description: Kados R10 GreenBee is vulnerable to SQL injection via the 'id_to_modify' parameter, enabling attackers to manipulate database queries and potentially extract or modify sensitive data.
date: "2026-04-05T21:16:47Z"
severities:
  - high
tags:
  - sqli
  - cve-2019-25692
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25692
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25692
  - https://www.exploit-db.com/exploits/46505
  - https://www.vulncheck.com/advisories/kados-r10-greenbee-sql-injection-via-id-to-modify-parameter
rules:
  - title: Detect Suspicious SQL Injection Attempt
    description: Detects potential SQL injection attempts by looking for common SQL keywords in the 'id_to_modify' parameter within web server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection via HTTP Request
    description: This rule detects potential SQL injection attempts by looking for common SQL injection payloads in HTTP requests.
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

Kados R10 GreenBee is susceptible to an SQL injection vulnerability (CVE-2019-25692) affecting the 'id_to_modify' parameter. An attacker can inject malicious SQL code into this parameter through crafted HTTP requests. Successful exploitation allows the attacker to manipulate database queries, potentially leading to unauthorized data access, modification, or deletion. This vulnerability poses a significant risk to organizations using Kados R10 GreenBee, as it could compromise the…
