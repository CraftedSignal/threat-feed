---
title: phpMyFAQ Unauthenticated SQL Injection via User-Agent Header
slug: 2024-01-phpmyfaq-sql-injection
description: Unauthenticated SQL injection vulnerability exists in phpMyFAQ <= 4.1.1 due to improper handling of the User-Agent header in BuiltinCaptcha, allowing attackers to inject malicious SQL payloads and potentially gain complete control of the datastore.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - unauthenticated
  - web-application
vendors:
  - phpMyFAQ
products:
  - phpMyFAQ
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-289f-fq7w-6q2w
rules:
  - title: phpMyFAQ Captcha API SQL Injection Attempt
    description: Detects potential SQL injection attempts in the phpMyFAQ Captcha API by monitoring for suspicious characters in the User-Agent header.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: phpMyFAQ Captcha API SQL Injection - Time Delay
    description: Detects potential SQL injection attempts in the phpMyFAQ Captcha API by monitoring for requests with abnormally long processing times.
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

phpMyFAQ versions 4.1.1 and earlier are vulnerable to unauthenticated SQL injection in the BuiltinCaptcha component. The vulnerability stems from the improper handling of the User-Agent header and client IP address in the `garbageCollector()` and `saveCaptcha()` methods within `phpmyfaq/src/phpMyFAQ/Captcha/BuiltinCaptcha.php`. These methods fail to sanitize user-supplied data before incorporating it into SQL queries, specifically a DELETE and an INSERT statement, respectively. An attacker can inject arbitrary SQL commands by crafting a malicious User-Agent header and sending a GET request to the `/api/captcha` endpoint. The vulnerability was verified against phpMyFAQ 4.2.0-alpha, demonstrating a significant time difference in response times between clean and injected requests. This issue allows attackers to potentially read sensitive data, manipulate database records, and gain complete control of the phpMyFAQ datastore.

## Attack Chain

1. An unauthenticated attacker crafts a malicious SQL payload.
2. The attacker injects the payload into the User-Agent header of an HTTP GET request.
3. The attacker sends the crafted GET request to the `/api/captcha` endpoint of the phpMyFAQ instance.
4. The `CaptchaController.php` processes the request, instantiating the `BuiltinCaptcha` class.
5. The `BuiltinCaptcha` class retrieves the unsanitized User-Agent header.
6. The `getCaptchaImage()` method calls both the `saveCaptcha()` and `garbageCollector()` methods.
7. These methods execute the SQL queries with the injected payload, due to the lack of sanitization.
8. The attacker leverages time-based blind SQL injection to extract sensitive data or manipulate database records.

## Impact

Successful exploitation of this vulnerability allows an attacker to perform unauthenticated remote SQL injection against the phpMyFAQ database. In a default installation, this includes the ability to read user credential hashes, the admin token, SMTP credentials, and the content of FAQ entries, including those marked as private or restricted. Attackers can also tamper with or wipe arbitrary rows within the database due to the ability to modify DELETE queries. The absence of authentication, CSRF protection, or rate limiting on the `/api/captcha` endpoint makes exploitation straightforward.

## Recommendation

- Apply the recommended fix provided in the advisory by implementing input sanitization using `Database::escape()` before interpolating values into SQL queries. Specifically, modify `phpmyfaq/src/phpMyFAQ/Captcha/BuiltinCaptcha.php:298-325` and `phpmyfaq/src/phpMyFAQ/Captcha/BuiltinCaptcha.php:330` as described in the advisory.
- Audit the entire codebase for instances of `sprintf` used in conjunction with SQL queries, as suggested by the advisory, to identify and remediate any other potential SQL injection vulnerabilities.
- Deploy the provided Sigma rule "phpMyFAQ Captcha API SQL Injection Attempt" to detect attempts to exploit this vulnerability by monitoring for suspicious User-Agent headers in requests to `/api/captcha`.
- Upgrade to a patched version of phpMyFAQ that addresses this vulnerability, if available.
