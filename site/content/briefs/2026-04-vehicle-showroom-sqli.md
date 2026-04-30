---
title: SQL Injection Vulnerability in Vehicle Showroom Management System 1.0
slug: 2026-04-vehicle-showroom-sqli
description: A remote attacker can exploit an SQL injection vulnerability (CVE-2026-6165) in code-projects Vehicle Showroom Management System 1.0 by manipulating the ID parameter in /util/Login_check.php, potentially leading to unauthorized data access and modification.
date: "2026-04-13T06:17:51Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sqli
  - web-application
  - cve-2026-6165
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6165
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6165
  - https://vuldb.com/vuln/357053
rules:
  - title: Detect SQL Injection Attempts in Login_check.php
    description: Detects potential SQL injection attempts by monitoring requests to /util/Login_check.php containing common SQL injection payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection via POST Request to Login_check.php
    description: Detects SQL injection attempts targeting Login_check.php via POST requests.
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

CVE-2026-6165 identifies an SQL injection vulnerability within the code-projects Vehicle Showroom Management System version 1.0. The vulnerability resides in the `/util/Login_check.php` file and can be exploited by manipulating the `ID` argument. Successful exploitation allows attackers to inject malicious SQL queries, potentially gaining unauthorized access to sensitive data, modifying database contents, or even executing arbitrary commands on the underlying server. As a publicly available exploit exists, the risk of exploitation is elevated, making it crucial for organizations using this software to implement mitigation measures. The scope of this vulnerability impacts any deployment of the affected Vehicle Showroom Management System version 1.0 exposed to network traffic.

## Attack Chain

1.  Attacker identifies a vulnerable Vehicle Showroom Management System 1.0 instance exposed on the network.
2.  The attacker crafts a malicious HTTP request targeting the `/util/Login_check.php` endpoint.
3.  The attacker injects SQL code into the `ID` parameter of the HTTP request, bypassing input validation.
4.  The web application processes the malicious SQL query without proper sanitization.
5.  The injected SQL code is executed against the underlying database.
6.  The attacker retrieves sensitive information from the database, such as user credentials or financial records.
7.  The attacker may modify database entries, such as altering prices or inventory.
8.  The attacker could potentially leverage the SQL injection to gain code execution on the server.

## Impact

Successful exploitation of CVE-2026-6165 can lead to a range of severe consequences. An attacker could gain unauthorized access to sensitive customer data, including personally identifiable information (PII) and financial details. Data breaches can result in significant financial losses, reputational damage, and legal liabilities. Furthermore, the ability to modify database contents could lead to manipulated sales figures, altered inventory, or even complete disruption of business operations. The vulnerability's potential for remote code execution poses the highest risk, allowing attackers to establish a persistent foothold within the organization's infrastructure.

## Recommendation

*   Apply appropriate input validation and sanitization techniques to the `ID` parameter in `/util/Login_check.php` to prevent SQL injection (CVE-2026-6165).
*   Deploy the provided Sigma rule to detect suspicious HTTP requests targeting `/util/Login_check.php` with potential SQL injection payloads.
*   Implement a web application firewall (WAF) to filter malicious traffic and block known SQL injection patterns.
*   Regularly audit and patch all software components to address known vulnerabilities.
*   Monitor web server logs for unusual activity and potential signs of exploitation.
