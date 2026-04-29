---
title: OpenDocMan 1.3.4 SQL Injection Vulnerability
slug: 2026-04-opendocman-sqli
description: OpenDocMan version 1.3.4 is vulnerable to SQL injection, allowing unauthenticated attackers to manipulate database queries via the 'where' parameter in search.php to extract sensitive information.
date: "2026-04-05T21:16:46Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - sqli
  - vulnerability
  - opendocman
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25684
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25684
  - https://sourceforge.net/projects/opendocman/files/
  - https://www.exploit-db.com/exploits/46500
  - https://www.vulncheck.com/advisories/opendocman-sql-injection-via-where-parameter
rules:
  - title: Detect SQL Injection Attempt in OpenDocMan search.php
    description: Detects potential SQL injection attempts by looking for specific SQL keywords in the 'where' parameter of requests to search.php in OpenDocMan.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenDocMan SQL Injection via GET Request to search.php
    description: This rule detects GET requests to search.php with a 'where' parameter that contains SQL keywords indicative of an injection attempt.
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

OpenDocMan 1.3.4 is susceptible to SQL injection attacks due to insufficient input validation. An unauthenticated attacker can inject malicious SQL code into the 'where' parameter of the `search.php` endpoint. This vulnerability allows attackers to bypass normal query restrictions, potentially leading to the extraction of sensitive data from the database. The vulnerability was published on 2026-04-05 and assigned CVE-2019-25684. Successful exploitation grants attackers unauthorized access to database contents without requiring authentication.

## Attack Chain

1.  The attacker identifies an OpenDocMan 1.3.4 instance.
2.  The attacker crafts a malicious HTTP GET request targeting the `/search.php` endpoint.
3.  The attacker injects SQL code into the `where` parameter of the GET request.
4.  The web server passes the crafted SQL query to the database without proper sanitization.
5.  The database executes the injected SQL code, potentially returning sensitive data.
6.  The attacker receives the database response containing the extracted information.
7.  The attacker analyzes the extracted data for sensitive information such as usernames, passwords, or confidential documents.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to the complete compromise of the OpenDocMan database. An attacker can access sensitive information, including user credentials and confidential documents, potentially impacting all users of the affected OpenDocMan instance. There are no specific details about victim counts or targeted sectors available, but the impact could be widespread, depending on the deployment of OpenDocMan.

## Recommendation

*   Apply input validation and sanitization to the `where` parameter in `search.php` to prevent SQL injection.
*   Deploy the Sigma rule to detect attempts to exploit CVE-2019-25684 by monitoring for suspicious SQL syntax in the 'where' parameter within web server logs.
*   Upgrade to a patched version of OpenDocMan that addresses this vulnerability when available.
*   Monitor web server logs for unusual activity targeting the `search.php` endpoint, as indicated in the attack chain.
