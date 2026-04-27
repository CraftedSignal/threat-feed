---
title: Unauthenticated SQL Injection Vulnerability in getinfo Endpoint (CVE-2026-33614)
slug: 2026-04-sql-injection-getinfo
description: An unauthenticated SQL Injection vulnerability (CVE-2026-33614) in the getinfo endpoint allows a remote attacker to execute arbitrary SQL commands due to improper neutralization of special elements, potentially leading to a total loss of confidentiality.
date: "2026-04-02T10:16:16Z"
severities:
  - critical
tags:
  - sql-injection
  - vulnerability
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-33614
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33614
  - https://certvde.com/de/advisories/VDE-2026-030
  - https://mbconnectline.csaf-tp.certvde.com/.well-known/csaf/white/2026/vde-2026-030.json
rules:
  - title: Detect Suspicious getinfo SQL Injection Attempts
    description: Detects potential SQL injection attempts targeting the getinfo endpoint by looking for common SQL keywords in the URI query.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Error Messages in Web Responses
    description: Detects potential SQL injection exploitation by identifying SQL error messages in the web server response.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-33614 describes an unauthenticated SQL Injection vulnerability present in the getinfo endpoint of an unspecified application. Discovered and reported by CERT VDE, the vulnerability stems from the improper neutralization of special elements within a SQL SELECT command. A remote, unauthenticated attacker can exploit this flaw to inject malicious SQL code, potentially gaining unauthorized access to sensitive data. Successful exploitation results in a total loss of confidentiality, as the…
