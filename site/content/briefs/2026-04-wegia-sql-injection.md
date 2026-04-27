---
title: WeGIA Web Manager SQL Injection Vulnerability (CVE-2026-35395)
slug: 2026-04-wegia-sql-injection
description: WeGIA web manager versions prior to 3.6.9 are vulnerable to SQL injection, allowing authenticated users to execute arbitrary SQL commands by directly interpolating the id_memorando parameter from $_REQUEST into SQL queries without validation, as identified by CVE-2026-35395.
date: "2026-04-06T21:16:21Z"
severities:
  - critical
tags:
  - cve-2026-35395
  - sql-injection
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-35395
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35395
  - https://github.com/LabRedesCefetRJ/WeGIA/security/advisories/GHSA-43jm-pcrq-w7gv
rules:
  - title: Detect Suspicious WeGIA SQL Injection Attempts
    description: Detects potential SQL injection attempts in WeGIA web application by monitoring for suspicious characters and keywords in the id_memorando parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WeGIA DespachoDAO.php Access with Potential SQL Injection
    description: Detects access to DespachoDAO.php with potentially malicious SQL injection attempts.
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

WeGIA (Web gerenciador para instituições assistenciais) is a web manager for charitable institutions. Versions prior to 3.6.9 are susceptible to a critical SQL injection vulnerability (CVE-2026-35395) found in the `dao/memorando/DespachoDAO.php` file. The `id_memorando` parameter, extracted from the `$_REQUEST` array, is directly incorporated into SQL queries without any validation or sanitization. This flaw enables authenticated users with low privileges to inject arbitrary SQL commands…
