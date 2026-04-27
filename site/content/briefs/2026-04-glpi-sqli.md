---
title: GLPI SQL Injection Vulnerability (CVE-2026-29047)
slug: 2026-04-glpi-sqli
description: GLPI versions 10.0.0 before 10.0.24 and 11.0.6 are vulnerable to SQL Injection (CVE-2026-29047) via the logs export feature, allowing authenticated users to potentially execute arbitrary SQL commands.
date: "2026-04-06T15:17:07Z"
severities:
  - high
tags:
  - glpi
  - sqli
  - cve-2026-29047
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-29047
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-29047
  - https://github.com/glpi-project/glpi/security/advisories/GHSA-3m49-qf92-vccr
rules:
  - title: Detect GLPI SQL Injection Attempt via Logs Export
    description: Detects potential SQL injection attempts targeting the GLPI logs export feature by monitoring for suspicious characters in the request URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: Detect GLPI SQL Injection via POST Request
    description: Detects potential SQL injection attempts targeting the GLPI via POST requests with SQL keywords.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1547.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

GLPI is a free asset and IT management software package.  CVE-2026-29047 affects GLPI versions 10.0.0 up to, but not including, 10.0.24, as well as version 11.0.6. An authenticated user can exploit a SQL injection vulnerability present in the logs export feature. Successful exploitation could allow an attacker to read sensitive data, modify database content, or even execute arbitrary commands on the underlying database server.  Organizations using vulnerable versions of GLPI should upgrade to…
