---
title: Smartshop 1 SQL Injection Vulnerability (CVE-2018-25341)
slug: 2026-05-smartshop-sqli
description: Smartshop version 1 is vulnerable to SQL injection (CVE-2018-25341), allowing unauthenticated attackers to execute arbitrary SQL queries via the id parameter in product.php, potentially leading to sensitive data extraction.
date: "2026-05-26T13:36:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve
  - web-application
products:
  - Smartshop 1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25341
rules:
  - title: Detect CVE-2018-25341 Exploitation — Smartshop SQL Injection Attempt
    description: Detects CVE-2018-25341 exploitation — SQL injection attempts in Smartshop product.php via the id parameter
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2018-25341 Exploitation — Smartshop SQL Injection with Comments
    description: Detects CVE-2018-25341 exploitation — SQL injection attempts in Smartshop product.php using comments
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Smartshop version 1 is vulnerable to SQL injection, as identified by CVE-2018-25341. This vulnerability allows an unauthenticated attacker to execute arbitrary SQL queries by injecting malicious SQL code into the `id` parameter of the `product.php` page via a GET request. The vulnerability exists due to insufficient input validation and sanitization of the `id` parameter. Successful exploitation can lead to the extraction of sensitive database information, including usernames and database names. This poses a significant risk to the confidentiality and integrity of the application's data. Defenders should prioritize patching or mitigating this vulnerability to prevent potential data breaches and unauthorized access.

## Attack Chain

1.  The attacker identifies a Smartshop version 1 instance.
2.  The attacker crafts a malicious GET request targeting the `product.php` endpoint.
3.  The GET request includes a SQL injection payload within the `id` parameter.
4.  The application fails to properly sanitize the `id` parameter.
5.  The unsanitized `id` parameter is passed directly into an SQL query.
6.  The attacker leverages a UNION-based SQL injection technique to extract data.
7.  The SQL query executes, returning database usernames or database names.
8.  The attacker obtains sensitive information from the database.

## Impact

Successful exploitation of this vulnerability allows an attacker to extract sensitive information from the Smartshop database. This may include usernames, passwords, customer data, or other confidential information. The impact can range from unauthorized data access to potential data breaches and financial losses. The vulnerability could be exploited by a wide range of attackers due to the lack of authentication requirements.

## Recommendation

*   Deploy the Sigma rule to detect exploitation attempts against the `product.php` endpoint targeting the `id` parameter, and tune for your environment.
*   Apply input validation and sanitization to the `id` parameter in `product.php` to prevent SQL injection.
*   Monitor web server logs for suspicious GET requests to `product.php` containing SQL injection payloads.
