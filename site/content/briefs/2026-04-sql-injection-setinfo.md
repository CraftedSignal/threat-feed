---
title: Unauthenticated SQL Injection Vulnerability in setinfo Endpoint
slug: 2026-04-sql-injection-setinfo
description: An unauthenticated remote attacker can exploit a SQL Injection vulnerability (CVE-2026-33615) in the setinfo endpoint by injecting malicious code into a SQL UPDATE command, leading to a total loss of integrity and availability.
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
  - id: CVE-2026-33615
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33615
  - https://certvde.com/de/advisories/VDE-2026-030
  - https://mbconnectline.csaf-tp.certvde.com/.well-known/csaf/white/2026/vde-2026-030.json
ioc_counts:
  email: 1
  url: 2
rules:
  - title: Detect Potential SQL Injection in setinfo Endpoint
    description: Detects potential SQL injection attempts in requests to the setinfo endpoint by looking for common SQL keywords.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Error Messages Indicating Potential Injection
    description: Detects SQL error messages in web server responses which may indicate successful or attempted SQL injection.
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

CVE-2026-33615 describes a critical security vulnerability affecting the `setinfo` endpoint. This vulnerability allows an unauthenticated remote attacker to inject malicious SQL code due to the improper neutralization of special elements within a SQL UPDATE command. The vulnerability was published on April 2, 2026. Successful exploitation can lead to complete data compromise, system downtime, and a total loss of integrity and availability. This vulnerability poses a significant risk to…
