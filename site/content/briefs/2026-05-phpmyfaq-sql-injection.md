---
title: Unauthenticated SQL Injection in phpMyFAQ via User-Agent Header
slug: 2026-05-phpmyfaq-sql-injection
description: phpMyFAQ versions before 4.1.2 are vulnerable to unauthenticated SQL injection via crafted User-Agent headers in the /api/captcha endpoint, allowing attackers to extract sensitive information.
date: "2026-05-15T19:19:20Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - phpMyFAQ
  - sql-injection
  - unauthenticated
  - CVE-2026-46364
  - web-application
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ < 4.1.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-46364
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-46364
rules:
  - title: Detects CVE-2026-46364 Exploitation — phpMyFAQ SQL Injection via User-Agent
    description: Detects CVE-2026-46364 exploitation — Detects SQL injection attempts in the User-Agent header when accessing the /api/captcha endpoint in phpMyFAQ.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-46364 Exploitation — phpMyFAQ Time-Based SQL Injection
    description: Detects CVE-2026-46364 exploitation — Detects potential time-based SQL injection attempts in the User-Agent header by looking for sleep commands.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

phpMyFAQ before version 4.1.2 is vulnerable to an unauthenticated SQL injection vulnerability in the `BuiltinCaptcha::garbageCollector()` and `BuiltinCaptcha::saveCaptcha()` methods. This vulnerability stems from the improper sanitization of User-Agent headers, which are then interpolated into DELETE and INSERT SQL queries. Exploitation occurs via the publicly accessible GET `/api/captcha` endpoint, which allows unauthenticated attackers to inject malicious SQL code through crafted User-Agent headers, leading to time-based blind SQL injection. Successful exploitation enables the extraction of sensitive data, potentially including user credentials, administrative tokens, and SMTP credentials stored within the database. This vulnerability poses a significant risk to the confidentiality and integrity of phpMyFAQ installations.

## Attack Chain

1. An unauthenticated attacker identifies a phpMyFAQ instance running a version prior to 4.1.2.
2. The attacker crafts a malicious HTTP GET request targeting the `/api/captcha` endpoint.
3. The crafted request includes a User-Agent header containing SQL injection payloads designed for time-based blind SQL injection.
4. phpMyFAQ's `BuiltinCaptcha::saveCaptcha()` method receives the request and processes the malicious User-Agent header.
5. The unsanitized User-Agent string is then interpolated directly into an INSERT query to store captcha data.
6. The SQL injection payload executes within the INSERT query, allowing the attacker to inject arbitrary SQL code.
7. The attacker uses time-based techniques (e.g., `SLEEP()`) to infer data from the database based on response times.
8. The attacker extracts sensitive information, such as user credentials, admin tokens, and SMTP credentials, from the database.

## Impact

Successful exploitation of this vulnerability allows attackers to extract sensitive information from the phpMyFAQ database. This includes user credentials, potentially granting unauthorized access to user accounts and administrative functions. Additionally, extracted SMTP credentials can be used to send malicious emails, and admin tokens can lead to full system compromise. Given the CVSS v3.1 base score of 9.8, this is a critical vulnerability, and successful attacks can lead to complete compromise of the application and data.

## Recommendation

*   Upgrade phpMyFAQ to version 4.1.2 or later to patch CVE-2026-46364.
*   Deploy the Sigma rule "Detects CVE-2026-46364 Exploitation — phpMyFAQ SQL Injection via User-Agent" to identify exploitation attempts in web server logs.
*   Deploy the Sigma rule "Detects CVE-2026-46364 Exploitation — phpMyFAQ Time-Based SQL Injection" to identify time-based SQL injection attempts in web server logs.
