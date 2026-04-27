---
title: GLPI Unauthenticated Time-Based Blind SQL Injection Vulnerability (CVE-2026-26263)
slug: 2026-04-glpi-sql-injection
description: GLPI versions 11.0.0 to before 11.0.6 are susceptible to an unauthenticated time-based blind SQL injection vulnerability in the search engine, allowing remote attackers to potentially extract sensitive information.
date: "2026-04-06T15:17:07Z"
severities:
  - high
tags:
  - sql-injection
  - glpi
  - cve-2026-26263
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-26263
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26263
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-346p-qj3v-9rxj
rules:
  - title: Detect GLPI SQL Injection Attempt via Search
    description: Detects potential SQL injection attempts against GLPI search functionality based on suspicious keywords in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect GLPI SQL Injection Attempt via POST Request
    description: Detects potential SQL injection attempts against GLPI search functionality using POST requests.
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

GLPI, a widely used free asset and IT management software, is vulnerable to a critical security flaw. Specifically, versions 11.0.0 to before 11.0.6 contain an unauthenticated time-based blind SQL injection vulnerability (CVE-2026-26263) within its search engine functionality. This vulnerability allows remote attackers to inject malicious SQL code without needing prior authentication. Exploitation could lead to unauthorized data access, modification, or deletion, potentially compromising the…
