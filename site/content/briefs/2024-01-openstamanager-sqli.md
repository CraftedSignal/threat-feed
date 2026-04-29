---
title: OpenSTAManager Time-Based Blind SQL Injection Vulnerability
slug: 2024-01-openstamanager-sqli
description: OpenSTAManager versions before 2.10.2 are susceptible to time-based blind SQL injection via the 'options[stato]' GET parameter, allowing authenticated attackers to extract sensitive database information.
date: "2026-04-02T14:16:26Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - openstamanager
  - sqli
  - cve-2026-28805
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28805
rules:
  - title: Detect OpenSTAManager SQL Injection Attempt
    description: Detects potential SQL injection attempts in OpenSTAManager by monitoring requests with SQL-related keywords in the options[stato] parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenSTAManager Time-Based SQL Injection
    description: Detects potential time-based SQL injection attempts in OpenSTAManager by monitoring requests with SQL-related keywords and SLEEP function in the options[stato] parameter.
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

OpenSTAManager, a management software for technical assistance and invoicing, contains a critical vulnerability that could lead to significant data breaches. Specifically, versions prior to 2.10.2 are vulnerable to Time-Based Blind SQL Injection (CVE-2026-28805) in its AJAX select handlers. The vulnerability exists due to the lack of sanitization, parameterization, or allowlist validation of the 'options[stato]' GET parameter. This allows an authenticated attacker to inject arbitrary SQL queries, potentially compromising the entire database. Successful exploitation allows an attacker to extract sensitive data like usernames, password hashes, and financial records. Organizations using affected versions of OpenSTAManager should upgrade to version 2.10.2 immediately to mitigate this risk.

## Attack Chain

1. An authenticated attacker identifies the vulnerable AJAX select handler within the OpenSTAManager application.
2. The attacker crafts a malicious HTTP GET request targeting the vulnerable endpoint, injecting SQL code into the `options[stato]` parameter (e.g., `options[stato]=%' AND SLEEP(5) AND '%'='`).
3. The server-side application concatenates the attacker-supplied SQL code directly into a SQL WHERE clause without proper sanitization.
4. The injected SQL `SLEEP()` function causes a time delay on the server, confirming the successful injection to the attacker.
5. The attacker refines the SQL injection payload to extract specific data, such as the database version or user credentials, using conditional `SLEEP()` statements and character-by-character extraction techniques.
6. The attacker iterates through the database structure and tables, extracting sensitive data like usernames and password hashes.
7. Using the extracted credentials, the attacker gains unauthorized access to administrative functions within OpenSTAManager.
8. The attacker exfiltrates financial records and other sensitive data from the compromised database.

## Impact

Successful exploitation of this vulnerability can lead to complete compromise of the OpenSTAManager database. This includes the potential exposure of sensitive customer data, financial records, and internal user credentials. The impact could range from financial loss and reputational damage to legal repercussions for failing to protect sensitive information. Given the CVSS v3.1 base score of 8.8, this is a critical vulnerability requiring immediate attention.

## Recommendation

*   Upgrade OpenSTAManager to version 2.10.2 or later to patch CVE-2026-28805.
*   Deploy the Sigma rule "Detect OpenSTAManager SQL Injection Attempt" to monitor for malicious requests containing SQL injection payloads targeting the `options[stato]` parameter (see rules).
*   Implement web application firewall (WAF) rules to block requests containing SQL injection patterns, specifically targeting the `options[stato]` GET parameter.
*   Review web server logs for unusual activity and suspicious requests containing SQL syntax within the `options[stato]` parameter.
