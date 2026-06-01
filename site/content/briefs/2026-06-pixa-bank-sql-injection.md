---
title: Pixa Bank 2.0 Unauthenticated SQL Injection Vulnerability
slug: 2026-06-pixa-bank-sql-injection
description: Pixa Bank 2.0 is vulnerable to SQL injection, allowing unauthenticated attackers to extract sensitive data by injecting SQL code into the 'rib' parameter via POST requests to the agence-ajax.php endpoint with UNION-based SQL payloads, potentially leading to the retrieval of user information such as names, email addresses, and phone numbers from the database.
date: "2026-06-01T22:19:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - vulnerability
  - web-application
vendors:
  - pixa
products:
  - Pixa Bank 2.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-49491
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-49491
  - https://packetstorm.news/files/id/220748/
  - https://pixastudio.com/
  - https://www.vulncheck.com/advisories/pixa-bank-sql-injection-via-agence-ajax-php-api
rules:
  - title: Detect Pixa Bank SQL Injection Attempts
    description: Detects potential SQL injection attempts targeting the Pixa Bank application by monitoring POST requests to the 'agence-ajax.php' endpoint with SQL keywords in the 'rib' parameter (CVE-2026-49491).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Pixa Bank SQL Injection - Error Responses
    description: Detects potential SQL injection attempts targeting Pixa Bank by monitoring for server error responses (5xx status codes) after POST requests containing SQL keywords to the vulnerable endpoint agence-ajax.php. This indicates that the SQL injection attempt caused a database error (CVE-2026-49491).
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

Pixa Bank 2.0 is susceptible to an SQL injection vulnerability (CVE-2026-49491) that enables unauthenticated attackers to extract sensitive information from the database. This vulnerability is present due to insufficient input validation on the 'rib' parameter. By crafting malicious POST requests to the `agence-ajax.php` endpoint, attackers can inject SQL code, specifically using UNION-based SQL injection techniques, to bypass security measures and directly query the database. Successful exploitation allows retrieval of user details, including names, email addresses, and phone numbers, which can then be used for identity theft, phishing campaigns, or further malicious activities. The vulnerability was reported in June 2026 and affects version 2.0 of Pixa Bank.

## Attack Chain

1.  The attacker identifies the `agence-ajax.php` endpoint.
2.  The attacker crafts a POST request to `agence-ajax.php` with a malicious SQL payload within the `rib` parameter.
3.  The SQL payload uses UNION-based techniques to extract data from other tables in the database.
4.  The server processes the request without proper sanitization of the 'rib' parameter.
5.  The database executes the injected SQL code.
6.  Sensitive data, such as user names, email addresses, and phone numbers, is retrieved from the database.
7.  The extracted data is included in the response from the server.
8.  The attacker parses the response to obtain the sensitive information.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to the compromise of sensitive user data, including names, email addresses, and phone numbers. The retrieved information can be used for identity theft, phishing attacks, or sold on the dark web. The vulnerability affects all installations of Pixa Bank 2.0 that have not been patched, potentially impacting a large number of users and financial transactions. The CVSS v3.1 score of 8.2 highlights the high severity of this vulnerability, emphasizing the potential for significant data breaches and reputational damage.

## Recommendation

*   Deploy the Sigma rule `Detect Pixa Bank SQL Injection Attempts` to identify and block malicious requests targeting the `agence-ajax.php` endpoint (Sigma rule).
*   Apply input validation and sanitization to the 'rib' parameter in `agence-ajax.php` to prevent SQL injection (CVE-2026-49491).
*   Monitor web server logs for POST requests to `agence-ajax.php` containing SQL keywords such as `UNION`, `SELECT`, `INSERT`, `UPDATE`, or `DELETE` in the `rib` parameter (webserver logs).
*   Implement parameterized queries or prepared statements to prevent SQL injection by ensuring that user-supplied data is treated as data, not as executable code (CVE-2026-49491).
