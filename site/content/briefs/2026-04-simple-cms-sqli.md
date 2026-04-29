---
title: Simple Content Management System 1.0 SQL Injection Vulnerability
slug: 2026-04-simple-cms-sqli
description: A remote SQL injection vulnerability exists in code-projects Simple Content Management System 1.0 due to improper handling of the ID argument in the /web/index.php file, allowing unauthenticated attackers to execute arbitrary SQL queries.
date: "2026-04-14T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - sqli
  - cve-2026-6183
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6183
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6183
  - https://code-projects.org/
  - https://github.com/Xmyronn/simple-cms-sqli-id-parameter
  - https://vuldb.com/submit/797264
  - https://vuldb.com/vuln/357106
  - https://vuldb.com/vuln/357106/cti
iocs:
  - type: url
    value: https://code-projects.org/
  - type: url
    value: https://github.com/Xmyronn/simple-cms-sqli-id-parameter
  - type: url
    value: https://vuldb.com/submit/797264
  - type: url
    value: https://vuldb.com/vuln/357106
  - type: url
    value: https://vuldb.com/vuln/357106/cti
ioc_counts:
  url: 5
rules:
  - title: Detect Simple CMS SQL Injection Attempt
    description: Detects potential SQL injection attempts against Simple CMS by looking for SQL keywords in the ID parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Outbound Connection After Simple CMS Exploit
    description: Detects suspicious outbound connections from the web server after a potential Simple CMS exploit.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A SQL injection vulnerability has been identified in code-projects Simple Content Management System version 1.0. The vulnerability resides in the `/web/index.php` file and can be exploited by manipulating the `ID` argument. An attacker can remotely inject malicious SQL queries, potentially leading to unauthorized data access, modification, or deletion. Public exploits are available, increasing the risk of exploitation. The affected software is a content management system, typically used for managing website content. Successful exploitation could compromise the entire website and its underlying database.

## Attack Chain

1.  An attacker identifies a Simple Content Management System 1.0 instance running online.
2.  The attacker crafts a malicious HTTP request targeting `/web/index.php` with a modified `ID` parameter containing SQL injection code.
3.  The webserver receives the request and passes the `ID` parameter to the application.
4.  The application fails to properly sanitize the `ID` parameter before using it in an SQL query.
5.  The injected SQL code is executed against the database server.
6.  The attacker extracts sensitive information from the database, such as usernames, passwords, and other confidential data.
7.  The attacker uses the compromised credentials or data to gain further access to the system.
8.  The attacker may modify data, deface the website, or install a web shell for persistent access and control.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to significant data breaches, website defacement, and complete compromise of the Simple Content Management System 1.0. An attacker could gain access to sensitive information, including user credentials, financial data, and other confidential information stored in the database. The number of affected installations is currently unknown, but given the public availability of the exploit, widespread exploitation is possible. This can result in financial losses, reputational damage, and legal liabilities for affected organizations.

## Recommendation

*   Inspect web server logs for requests to `/web/index.php` containing suspicious characters or SQL keywords in the `ID` parameter to detect potential exploitation attempts (Sigma rule: "Detect Simple CMS SQL Injection Attempt").
*   Apply input validation and sanitization to the `ID` parameter in `/web/index.php` to prevent SQL injection attacks.
*   Monitor network traffic for outbound connections originating from the web server to unusual destinations, which may indicate data exfiltration after successful exploitation (Sigma rule: "Detect Outbound Connection After Simple CMS Exploit").
*   Review the GitHub exploit URL (https://github.com/Xmyronn/simple-cms-sqli-id-parameter) to understand the attack vector and potential payload.
*   Implement a web application firewall (WAF) rule to block requests containing malicious SQL injection patterns targeting the `/web/index.php` endpoint.
