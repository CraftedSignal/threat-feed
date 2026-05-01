---
title: SourceCodester Pharmacy Sales and Inventory System SQL Injection Vulnerability
slug: 2026-05-pharmacy-sqli
description: SourceCodester Pharmacy Sales and Inventory System 1.0 is vulnerable to remote SQL injection via the ID parameter in the /ajax.php?action=delete_customer endpoint, allowing attackers to potentially read, modify, or delete database information.
date: "2026-05-01T05:16:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - vulnerability
vendors:
  - SourceCodester
products:
  - Pharmacy Sales and Inventory System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7549
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7549
  - https://github.com/khairulazly760530-cell/cves/issues/3
  - https://vuldb.com/vuln/360359
rules:
  - title: Detect SQL Injection Attempts in Pharmacy Sales System
    description: Detects potential SQL injection attempts targeting the /ajax.php?action=delete_customer endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Error Messages in Web Server Logs
    description: Detects SQL injection attempts based on common error messages returned by the database.
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

On May 1, 2026, a SQL injection vulnerability, CVE-2026-7549, was disclosed in SourceCodester Pharmacy Sales and Inventory System version 1.0. The vulnerability resides in the `/ajax.php?action=delete_customer` endpoint, where the `ID` parameter is susceptible to manipulation, enabling remote attackers to inject arbitrary SQL commands. Publicly available exploit code exists, increasing the risk of exploitation. Successful exploitation can lead to unauthorized data access, modification, or deletion within the application's database. This vulnerability is particularly concerning due to the sensitive nature of pharmacy data, potentially impacting confidentiality, integrity, and availability.

## Attack Chain

1.  Attacker identifies the vulnerable `/ajax.php?action=delete_customer` endpoint in SourceCodester Pharmacy Sales and Inventory System 1.0.
2.  Attacker crafts a malicious HTTP request targeting the vulnerable endpoint.
3.  The malicious request includes a manipulated `ID` parameter containing a SQL injection payload.
4.  The application fails to properly sanitize the `ID` parameter before incorporating it into a SQL query.
5.  The injected SQL code is executed against the application's database.
6.  The attacker gains unauthorized access to sensitive data, such as customer information, prescription details, or inventory levels.
7.  The attacker may modify or delete data within the database, potentially disrupting pharmacy operations or causing data integrity issues.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-7549) can lead to the complete compromise of the SourceCodester Pharmacy Sales and Inventory System database. Attackers could potentially exfiltrate sensitive patient data, modify prescription information, or disrupt pharmacy operations by deleting critical data. The vulnerability has a CVSS v3.1 score of 7.3 (HIGH), indicating a significant risk. The number of victims and specific sectors targeted remain unknown, but any pharmacy using the affected version is potentially at risk.

## Recommendation

*   Apply input validation and sanitization to all user-supplied input, especially the `ID` parameter in `/ajax.php?action=delete_customer`, to prevent SQL injection (CWE-89).
*   Deploy the Sigma rule "Detect SQL Injection Attempts in Pharmacy Sales System" to identify and block malicious requests targeting the vulnerable endpoint.
*   Upgrade to a patched version of SourceCodester Pharmacy Sales and Inventory System that addresses CVE-2026-7549 once available.
*   Monitor web server logs for suspicious activity, such as unusual requests to `/ajax.php?action=delete_customer`, to detect potential exploitation attempts.
