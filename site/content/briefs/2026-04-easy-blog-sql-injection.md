---
title: Easy Blog Site SQL Injection Vulnerability (CVE-2026-5805)
slug: 2026-04-easy-blog-sql-injection
description: A SQL injection vulnerability (CVE-2026-5805) exists in code-projects Easy Blog Site up to version 1.0, allowing remote attackers to manipulate the 'Name' argument in the /users/contact_us.php file for unauthorized database access.
date: "2026-04-08T21:17:02Z"
severities:
  - high
exploited: true
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
  - id: CVE-2026-5805
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5805
  - https://code-projects.org/
  - https://github.com/ahmadmarz10-hub/CVEsMarz/blob/main/SQL%20Injection%20in%20Easy%20Blog%20Site%20PHP%20name%20Parameter.md
  - https://vuldb.com/submit/787031
  - https://vuldb.com/vuln/356243
  - https://vuldb.com/vuln/356243/cti
rules:
  - title: Detect SQL Injection Attempt in Easy Blog Site Contact Form
    description: Detects potential SQL injection attempts targeting the /users/contact_us.php file in Easy Blog Site by looking for suspicious characters and SQL keywords in the request.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Error Messages
    description: Detects SQL injection attempts based on SQL error messages in the web server logs.
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

A SQL injection vulnerability, identified as CVE-2026-5805, affects code-projects Easy Blog Site versions up to 1.0. The vulnerability resides in the `/users/contact_us.php` file and can be exploited by manipulating the `Name` argument. This allows a remote attacker to inject malicious SQL queries, potentially leading to unauthorized access to the database, data modification, or even complete system compromise. The availability of a public exploit increases the risk of active exploitation. Defenders should prioritize patching or mitigating this vulnerability to prevent potential attacks.

## Attack Chain

1.  Attacker identifies the vulnerable `contact_us.php` endpoint on the Easy Blog Site.
2.  Attacker crafts a malicious HTTP POST request targeting `/users/contact_us.php`.
3.  The POST request includes the `Name` parameter with a SQL injection payload.
4.  The application fails to properly sanitize or validate the `Name` parameter.
5.  The unsanitized input is incorporated into a SQL query executed by the application.
6.  The injected SQL code modifies the intended query, potentially bypassing authentication or accessing sensitive data.
7.  The database executes the modified query, returning sensitive information or modifying data.
8.  The attacker retrieves the information from the server response, achieving unauthorized access to the database.

## Impact

Successful exploitation of this SQL injection vulnerability could allow an attacker to read sensitive data from the database, modify existing data, or even execute arbitrary code on the server. The impact ranges from information disclosure to complete system compromise, depending on the database privileges and the attacker's skill. This can lead to data breaches, financial loss, and reputational damage. Given the availability of a public exploit, organizations using Easy Blog Site are at immediate risk.

## Recommendation

*   Apply any available patches or updates for code-projects Easy Blog Site to address CVE-2026-5805 (see references).
*   Deploy the provided Sigma rule to detect SQL injection attempts targeting the `/users/contact_us.php` endpoint by analyzing web server logs.
*   Implement input validation and sanitization on the `Name` parameter within the `/users/contact_us.php` file to prevent SQL injection attacks.
*   Monitor web server logs for suspicious activity related to SQL injection attempts (e.g., error messages, unusual characters in requests) to identify potential exploitation attempts.
