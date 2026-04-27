---
title: SQL Injection Vulnerability in itsourcecode Payroll Management System 1.0 (CVE-2026-5237)
slug: 2026-03-payroll-sqli
description: A SQL injection vulnerability (CVE-2026-5237) exists in itsourcecode Payroll Management System 1.0, allowing remote attackers to execute arbitrary SQL commands by manipulating the ID parameter in the /manage_user.php file.
date: "2026-03-31T23:17:11Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
  - payroll-system
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5237
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5237
  - https://github.com/K4ptor/itsourcecode-Payroll-Management-System-V1.0-SQL-Injection
  - https://vuldb.com/vuln/354388
rules:
  - title: Detect SQL Injection Attempts via URI
    description: Detects potential SQL injection attempts by identifying requests with SQL keywords in the URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Errors
    description: Detects SQL errors that may indicate successful or attempted SQL injection.
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

itsourcecode Payroll Management System 1.0 is vulnerable to SQL injection, specifically within the `/manage_user.php` file. The vulnerability, identified as CVE-2026-5237, stems from improper sanitization of the `ID` parameter. A remote attacker can exploit this flaw to inject arbitrary SQL commands into the application's database queries. Publicly available exploit code exists, increasing the risk of exploitation. This vulnerability allows attackers to potentially compromise the entire…
