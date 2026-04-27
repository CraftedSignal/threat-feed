---
title: SQL Injection Vulnerability in Faculty Management System
slug: 2026-04-faculty-mgmt-sqli
description: A remote attacker can exploit an SQL injection vulnerability (CVE-2026-6167) in the code-projects Faculty Management System 1.0 by manipulating the ID argument in the /subject-print.php file, potentially leading to data exfiltration or modification.
date: "2026-04-13T07:16:51Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6167
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6167
  - https://vuldb.com/vuln/357055
rules:
  - title: Detect SQL Injection Attempts in Faculty Management System
    description: Detects potential SQL injection attempts targeting the /subject-print.php endpoint by looking for common SQL keywords in the ID parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Error Messages Indicating Injection Success
    description: Detects potential successful SQL injection by looking for SQL error messages in the server response.
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

The code-projects Faculty Management System 1.0 is vulnerable to SQL injection (CVE-2026-6167) within the `/subject-print.php` file. The vulnerability stems from improper sanitization of the `ID` argument, allowing a remote attacker to inject arbitrary SQL commands. This exploit has been publicly disclosed, increasing the risk of widespread exploitation. Given the sensitive nature of data managed by faculty management systems, successful exploitation could lead to significant data breaches…
