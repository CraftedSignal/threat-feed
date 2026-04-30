---
title: SQL Injection Vulnerability in Faculty Management System
slug: 2026-04-faculty-mgmt-sqli
description: A remote attacker can exploit an SQL injection vulnerability (CVE-2026-6167) in the code-projects Faculty Management System 1.0 by manipulating the ID argument in the /subject-print.php file, potentially leading to data exfiltration or modification.
date: "2026-04-13T07:16:51Z"
severities:
  - high
type: advisory
types:
  - advisory
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

The code-projects Faculty Management System 1.0 is vulnerable to SQL injection (CVE-2026-6167) within the `/subject-print.php` file. The vulnerability stems from improper sanitization of the `ID` argument, allowing a remote attacker to inject arbitrary SQL commands. This exploit has been publicly disclosed, increasing the risk of widespread exploitation. Given the sensitive nature of data managed by faculty management systems, successful exploitation could lead to significant data breaches, system compromise, and disruption of academic operations. The lack of required authentication to trigger the vulnerability makes it particularly dangerous.

## Attack Chain

1.  The attacker identifies a vulnerable instance of code-projects Faculty Management System 1.0 accessible over the internet.
2.  The attacker crafts a malicious HTTP GET request targeting the `/subject-print.php` endpoint.
3.  The malicious request includes a modified `ID` parameter containing SQL injection payloads. For example, `ID=1' OR '1'='1`.
4.  The web server processes the request and passes the unsanitized `ID` parameter to the underlying SQL database.
5.  The injected SQL code is executed by the database, potentially allowing the attacker to bypass authentication or access unauthorized data.
6.  The attacker leverages the SQL injection to extract sensitive data from the database, such as usernames, passwords, student records, or financial information.
7.  The attacker may use the extracted credentials to gain administrative access to the application.
8.  Finally, the attacker could modify or delete data within the database, exfiltrate data, or pivot to other systems within the network.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-6167) in code-projects Faculty Management System 1.0 can lead to severe consequences. An attacker could potentially access and exfiltrate sensitive student and faculty data, modify grades, compromise user accounts, and disrupt academic operations. The public availability of the exploit increases the likelihood of widespread attacks targeting vulnerable systems, potentially impacting numerous educational institutions.

## Recommendation

*   Inspect web server logs for suspicious HTTP requests targeting `/subject-print.php` with unusual characters or SQL keywords in the `ID` parameter to detect potential exploitation attempts. Use the provided Sigma rule to facilitate this.
*   Implement a web application firewall (WAF) rule to block requests containing SQL injection payloads targeting `/subject-print.php`.
*   Apply input validation and sanitization to the `ID` parameter in `/subject-print.php` to prevent SQL injection, effectively patching CVE-2026-6167.
*   Monitor database logs for unusual queries originating from the web application server that could indicate successful SQL injection.
