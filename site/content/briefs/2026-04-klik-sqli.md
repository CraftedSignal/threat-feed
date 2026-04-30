---
title: KLiK SocialMediaWebsite SQL Injection Vulnerability (CVE-2026-7002)
slug: 2026-04-klik-sqli
description: KLiK SocialMediaWebsite up to version 1.0.1 is vulnerable to SQL injection via manipulation of the c_id argument in the /includes/get_message_ajax.php file, specifically affecting the Private Message Handler component, which can be exploited remotely.
date: "2026-04-26T14:30:00Z"
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
  - klik
products:
  - SocialMediaWebsite (up to 1.0.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7002
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7002
  - https://vuldb.com/vuln/359561
  - https://vuldb.com/vuln/359561/cti
rules:
  - title: Detect SQL Injection Attempt in KLiK SocialMediaWebsite
    description: Detects potential SQL injection attempts targeting the /includes/get_message_ajax.php endpoint in KLiK SocialMediaWebsite by looking for SQL keywords in the c_id parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempt in KLiK SocialMediaWebsite - Blind SQLi
    description: Detects potential blind SQL injection attempts targeting the /includes/get_message_ajax.php endpoint in KLiK SocialMediaWebsite by looking for time-based SQL keywords in the c_id parameter.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

KLiK SocialMediaWebsite version 1.0.1 and earlier is susceptible to a SQL injection vulnerability (CVE-2026-7002) affecting the Private Message Handler component. This vulnerability resides within the `/includes/get_message_ajax.php` file, and is triggered by manipulating the `c_id` argument. The attack can be launched remotely without authentication, potentially allowing unauthorized access to sensitive data within the application's database. Defenders should prioritize identifying and mitigating this vulnerability to prevent potential data breaches and unauthorized access to user information. The vulnerability was published on April 25, 2026.

## Attack Chain

1.  An attacker identifies a KLiK SocialMediaWebsite instance running version 1.0.1 or earlier.
2.  The attacker crafts a malicious HTTP request targeting the `/includes/get_message_ajax.php` endpoint.
3.  The attacker injects a SQL payload into the `c_id` parameter of the HTTP request.
4.  The web server processes the request and passes the malicious SQL query to the database.
5.  The database executes the injected SQL query without proper sanitization, leading to unintended data retrieval or modification.
6.  The attacker retrieves sensitive information from the database, such as user credentials or private messages.
7.  The attacker may use the stolen credentials to gain unauthorized access to user accounts.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to unauthorized access to sensitive data stored in the KLiK SocialMediaWebsite database. This could include user credentials, private messages, and other personal information. An attacker could potentially gain complete control over the application's data, leading to data breaches, identity theft, and other malicious activities. Given the wide use of social media platforms, a successful attack could affect a large number of users.

## Recommendation

*   Apply any available patches or updates for KLiK SocialMediaWebsite to address CVE-2026-7002.
*   Implement proper input validation and sanitization techniques to prevent SQL injection attacks.
*   Deploy the Sigma rule to detect attempts to exploit this SQL injection vulnerability by monitoring web server logs for suspicious requests targeting `/includes/get_message_ajax.php` with potentially malicious SQL payloads in the `c_id` parameter.
*   Monitor web server logs for HTTP requests to `/includes/get_message_ajax.php` containing SQL keywords (e.g., `SELECT`, `UNION`, `UPDATE`, `INSERT`, `DELETE`) in the `c_id` parameter.
