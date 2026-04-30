---
title: SQL Injection Vulnerability in Car Rental Project 1.0 (CVE-2026-5634)
slug: 2026-04-car-rental-sqli
description: A remote SQL injection vulnerability (CVE-2026-5634) exists in projectworlds Car Rental Project 1.0 via the fname parameter in /book_car.php, allowing unauthenticated attackers to potentially read, modify, or delete database information.
date: "2026-04-06T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sqli
  - web-application
  - cve-2026-5634
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5634
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5634
  - https://github.com/eqiya17/collection-of-vulnerabilities/issues/12
  - https://vuldb.com/submit/785863
  - https://vuldb.com/vuln/355422
  - https://vuldb.com/vuln/355422/cti
iocs:
  - type: url
    value: https://github.com/eqiya17/collection-of-vulnerabilities/issues/12
  - type: url
    value: https://vuldb.com/submit/785863
  - type: url
    value: https://vuldb.com/vuln/355422
  - type: url
    value: https://vuldb.com/vuln/355422/cti
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 1
  url: 4
rules:
  - title: Detect SQL Injection Attempts in Car Rental Project via fname Parameter
    description: Detects potential SQL injection attempts in the /book_car.php endpoint by monitoring for SQL syntax in the fname parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection UNION Based in Car Rental Project via fname Parameter
    description: Detects potential SQL injection attempts with UNION clauses in the /book_car.php endpoint by monitoring for SQL syntax in the fname parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A publicly disclosed SQL injection vulnerability affects projectworlds Car Rental Project version 1.0. This vulnerability, identified as CVE-2026-5634, resides in the `/book_car.php` file, specifically within the parameter handler. An attacker can remotely manipulate the `fname` argument to inject arbitrary SQL commands. Given the availability of exploit code, the risk of exploitation is elevated. Successful exploitation could lead to unauthorized data access, modification, or deletion, potentially compromising the entire application and its data. Defenders need to focus on detecting and preventing malicious requests targeting the vulnerable endpoint.

## Attack Chain

1.  An unauthenticated attacker identifies the vulnerable `/book_car.php` endpoint.
2.  The attacker crafts a malicious HTTP GET or POST request to `/book_car.php`, injecting SQL code into the `fname` parameter. For example, `fname=value' OR '1'='1`.
3.  The web server processes the request and passes the tainted `fname` parameter to the application's SQL query.
4.  Due to the lack of proper input sanitization, the injected SQL code is executed by the database server.
5.  The attacker can leverage the SQL injection vulnerability to bypass authentication, extract sensitive data (e.g., user credentials, car availability), or modify data (e.g., alter booking information, escalate privileges).
6.  The database server returns the results of the injected SQL query to the application.
7.  The application displays the results to the attacker, or uses them internally to further the attack.
8.  The attacker gains unauthorized access to the application's data and functionality, potentially leading to complete compromise.

## Impact

Successful exploitation of CVE-2026-5634 can lead to significant data breaches, data manipulation, and service disruption. An attacker could potentially gain access to sensitive customer data, including personal information and booking details. This can result in financial losses, reputational damage, and legal liabilities for the affected organization. The number of potential victims is dependent on the user base of the affected Car Rental Project 1.0 installation.

## Recommendation

*   Inspect web server logs for suspicious requests containing SQL syntax within the `fname` parameter targeting `/book_car.php` to identify potential exploitation attempts.
*   Deploy the provided Sigma rule to detect attempts to exploit the SQL injection vulnerability by monitoring web server logs (cs-uri-query).
*   Apply input validation and sanitization to the `fname` parameter in `/book_car.php` to prevent SQL injection attacks.
*   Consider using a Web Application Firewall (WAF) to filter out malicious requests targeting the vulnerable endpoint.
*   Upgrade to a patched version of Car Rental Project that addresses CVE-2026-5634, if available.
