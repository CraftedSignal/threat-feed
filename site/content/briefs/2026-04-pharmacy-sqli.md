---
title: SourceCodester Pharmacy Sales and Inventory System SQL Injection Vulnerability
slug: 2026-04-pharmacy-sqli
description: SourceCodester Pharmacy Sales and Inventory System 1.0 is vulnerable to SQL injection via the ID parameter in the /ajax.php?action=save_type endpoint, allowing remote attackers to execute arbitrary SQL commands.
date: "2026-04-27T14:16:56Z"
severities:
  - high
tags:
  - sqli
  - vulnerability
  - web-application
vendors:
  - SourceCodester
products:
  - Pharmacy Sales and Inventory System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-7128
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7128
  - https://github.com/lonelyuan/vunls/issues/13
  - https://vuldb.com/vuln/359727
rules:
  - title: Detect SQL Injection Attempt in Pharmacy Sales System
    description: Detects potential SQL injection attempts targeting the /ajax.php endpoint by looking for specific SQL keywords in the query string.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Vulnerable AJAX Endpoint
    description: This rule detects access to the specific vulnerable endpoint in SourceCodester Pharmacy Sales and Inventory System.
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

A SQL injection vulnerability has been identified in SourceCodester Pharmacy Sales and Inventory System version 1.0. The vulnerability resides in the `/ajax.php?action=save_type` endpoint and is triggered by manipulating the `ID` argument. Successful exploitation allows a remote attacker to inject and execute arbitrary SQL commands within the application's database. Publicly available exploits exist, increasing the likelihood of exploitation. This vulnerability poses a significant risk to…
