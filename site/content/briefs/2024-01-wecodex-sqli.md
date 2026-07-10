---
title: Wecodex Restaurant CMS 1.0 SQL Injection Vulnerability
slug: 2024-01-wecodex-sqli
description: Wecodex Restaurant CMS 1.0 is vulnerable to SQL injection via the username parameter, allowing unauthenticated attackers to extract sensitive database information by sending crafted POST requests to the login endpoint.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - cve-2018-25185
  - webserver
vendors:
  - Wecodex
products:
  - Wecodex Restaurant CMS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25185
  - https://www.exploit-db.com/exploits/44730
  - https://www.vulncheck.com/advisories/wecodex-restaurant-cms-sql-injection-via-login
rules:
  - title: Detect Wecodex Restaurant CMS SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the Wecodex Restaurant CMS login endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1211
    data_sources:
      - webserver
      - linux
  - title: Detect Time-Based Blind SQL Injection in Wecodex CMS
    description: Detects time-based blind SQL injection attempts by identifying requests with 'sleep()' function calls.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1211
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Wecodex Restaurant CMS version 1.0 is susceptible to SQL injection. The vulnerability, identified as CVE-2018-25185, enables unauthenticated attackers to inject malicious SQL code into the username parameter of the login form. This allows attackers to manipulate database queries and potentially extract sensitive information. The vulnerability exists because the application fails to properly sanitize user-supplied input before using it in a database query. The attack involves crafting a specific POST request to the login endpoint with a malicious SQL payload. This vulnerability was published on March 26, 2026, highlighting its continued relevance for systems running the vulnerable version. Exploitation can lead to complete compromise of the database.

## Attack Chain

1.  Attacker identifies a Wecodex Restaurant CMS 1.0 instance.
2.  Attacker crafts a malicious SQL payload designed for boolean-based or time-based blind SQL injection.
3.  Attacker sends a POST request to the login endpoint, injecting the SQL payload into the username parameter.
4.  The server processes the request without proper sanitization, executing the injected SQL code.
5.  Attacker analyzes the server's response based on boolean logic or response time to infer database structure and content.
6.  Attacker refines the SQL payload to extract sensitive data such as usernames, passwords, and customer information.
7.  Attacker uses the extracted credentials to gain unauthorized access to the application's administrative interface.
8.  Attacker potentially exfiltrates sensitive data or makes unauthorized changes to the application's database.

## Impact

Successful exploitation of this SQL injection vulnerability allows attackers to extract sensitive database information, including usernames, passwords, and customer details. This can lead to unauthorized access to the application's administrative interface, data breaches, and potential financial loss. The lack of authentication required to exploit the vulnerability increases the risk. While the exact number of victims is unknown, any organization using Wecodex Restaurant CMS 1.0 is potentially at risk.

## Recommendation

*   Apply appropriate input validation and sanitization techniques to all user-supplied input, especially within database queries.
*   Deploy the Sigma rule "Detect Wecodex Restaurant CMS SQL Injection Attempt" to identify potential exploitation attempts (see below).
*   Implement parameterized queries or prepared statements to prevent SQL injection vulnerabilities.
*   Consider using a web application firewall (WAF) to filter out malicious requests targeting the login endpoint.
*   Upgrade to a patched version of Wecodex Restaurant CMS or migrate to a more secure CMS solution if available from the vendor.
*   Monitor web server logs (cs-uri-query, cs-uri-stem, cs-method) for suspicious POST requests containing SQL syntax to the login endpoint.
