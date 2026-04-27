---
title: Krayin CRM v2.2.x SQL Injection Vulnerability
slug: 2026-04-krayin-sqli
description: Krayin CRM v2.2.x is vulnerable to SQL injection via the rotten_lead parameter in /Lead/LeadDataGrid.php, potentially allowing attackers to read sensitive data.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - sql-injection
  - cve-2026-38528
  - krayin-crm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-38528
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-38528
  - https://github.com/TREXNEGRO/Security-Advisories/tree/main/CVE-2026-38528
  - https://github.com/krayin/laravel-crm
rules:
  - title: Detect Krayin CRM SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the /Lead/LeadDataGrid.php endpoint in Krayin CRM.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Krayin CRM Error Based SQL Injection
    description: Detects error-based SQL injection attempts targeting Krayin CRM.
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

Krayin CRM v2.2.x is susceptible to a SQL injection vulnerability identified as CVE-2026-38528. The vulnerability resides in the `/Lead/LeadDataGrid.php` script, specifically within the `rotten_lead` parameter. An attacker could exploit this vulnerability by injecting malicious SQL queries, potentially gaining unauthorized access to sensitive information stored within the CRM database. The CVSS v3.1 score is 7.1, indicating a high severity level. Successful exploitation requires a low level of…
