---
title: code-projects Vehicle Showroom Management System SQL Injection Vulnerability (CVE-2026-6151)
slug: 2026-04-vehicle-showroom-sqli
description: CVE-2026-6151 is a SQL injection vulnerability affecting code-projects Vehicle Showroom Management System 1.0, which can be exploited by manipulating the CUSTOMER_ID argument in the `/util/PaymentStatusFunction.php` file, leading to potential data compromise.
date: "2026-04-13T03:16:02Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve-2026-6151
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6151
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6151
  - https://vuldb.com/vuln/357031
rules:
  - title: Detect Suspicious Payment Status Function SQL Injection
    description: Detects potential SQL injection attempts targeting the /util/PaymentStatusFunction.php file by looking for SQL keywords in the CUSTOMER_ID parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection via URI keywords
    description: Detects SQL Injection attempts via keywords in URI
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

A SQL injection vulnerability, CVE-2026-6151, has been identified in code-projects Vehicle Showroom Management System version 1.0. This vulnerability specifically impacts the `/util/PaymentStatusFunction.php` file, where manipulation of the `CUSTOMER_ID` argument can lead to arbitrary SQL command execution. The vulnerability allows for remote exploitation without authentication. Public exploits are available, increasing the risk of widespread exploitation. Successful exploitation could lead to unauthorized data access, modification, or deletion. This vulnerability poses a significant threat to organizations using the affected Vehicle Showroom Management System.

## Attack Chain

1. An attacker identifies a vulnerable instance of Vehicle Showroom Management System 1.0.
2. The attacker crafts a malicious HTTP request targeting `/util/PaymentStatusFunction.php`.
3. The crafted request includes a SQL injection payload within the `CUSTOMER_ID` parameter.
4. The web server processes the request without proper sanitization of the `CUSTOMER_ID` input.
5. The injected SQL code is executed against the underlying database.
6. The attacker gains unauthorized access to sensitive data within the database.
7. The attacker may modify existing data, potentially altering financial records or user accounts.
8. The attacker may exfiltrate stolen data, compromising confidentiality and potentially violating data protection regulations.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to unauthorized access to sensitive data, including customer information, financial records, and system configurations. Attackers could modify data to conduct fraud, steal personally identifiable information (PII), or disrupt business operations. The vulnerability has a high CVSS score of 7.3, indicating a significant risk to affected systems. Exploitation could lead to regulatory fines, reputational damage, and significant financial losses.

## Recommendation

*   Deploy the Sigma rule `Detect Suspicious Payment Status Function SQL Injection` to identify exploitation attempts targeting the `/util/PaymentStatusFunction.php` file (Sigma rule).
*   Apply input validation and sanitization to the `CUSTOMER_ID` parameter in the `/util/PaymentStatusFunction.php` file to prevent SQL injection (CVE-2026-6151).
*   Monitor web server logs for unusual requests to `/util/PaymentStatusFunction.php` that contain suspicious characters or SQL keywords (webserver log source).
*   Implement a web application firewall (WAF) to filter malicious requests targeting the vulnerable endpoint.
