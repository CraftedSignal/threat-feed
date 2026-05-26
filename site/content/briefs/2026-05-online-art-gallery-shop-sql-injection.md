---
title: Online Art Gallery Shop 1.0 SQL Injection Vulnerability (CVE-2026-9364)
slug: 2026-05-online-art-gallery-shop-sql-injection
description: A SQL injection vulnerability (CVE-2026-9364) exists in projectworlds Online Art Gallery Shop version 1.0, specifically in the /admin/adminHome.php file, which can be exploited remotely by manipulating the social_linked argument, potentially leading to unauthorized data access or modification.
date: "2026-05-26T13:46:04Z"
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
  - projectworlds
products:
  - Online Art Gallery Shop 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
cves:
  - id: CVE-2026-9364
    cvss: 7.3
    epss: 0.00028
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9364
  - https://github.com/Quafather/cve/issues/1
  - https://vuldb.com/submit/813133
  - https://vuldb.com/vuln/365327
  - https://vuldb.com/vuln/365327/cti
rules:
  - title: Detects CVE-2026-9364 Exploitation — SQL Injection Attempt in Online Art Gallery Shop
    description: Detects CVE-2026-9364 exploitation — SQL injection attempts targeting the social_linked parameter in /admin/adminHome.php
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
  - title: Detects CVE-2026-9364 Exploitation — SQL Injection with Encoded Characters
    description: Detects CVE-2026-9364 exploitation — SQL injection attempts in Online Art Gallery Shop via encoded characters
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
rules_count: 2
---

A SQL injection vulnerability, identified as CVE-2026-9364, has been discovered in projectworlds Online Art Gallery Shop version 1.0. This vulnerability resides in the `/admin/adminHome.php` file and is triggered by manipulating the `social_linked` argument. The vulnerability allows for remote exploitation, enabling attackers to inject malicious SQL queries into the application's database interactions. An exploit is publicly available, making exploitation more likely. This poses a significant risk to organizations using the affected software, potentially leading to data breaches and unauthorized access to sensitive information.

## Attack Chain

1.  The attacker identifies a vulnerable instance of Online Art Gallery Shop 1.0.
2.  The attacker crafts a malicious HTTP request targeting `/admin/adminHome.php`.
3.  The request includes a crafted `social_linked` parameter containing SQL injection payloads.
4.  The server-side application processes the request without proper sanitization of the `social_linked` parameter.
5.  The unsanitized input is incorporated into a SQL query executed against the application's database.
6.  The injected SQL commands are executed, potentially allowing the attacker to bypass authentication, extract sensitive data, or modify existing records.
7.  The attacker leverages the SQL injection vulnerability to retrieve user credentials or other sensitive data.
8.  The attacker uses the compromised credentials to gain unauthorized access to the application's administrative interface.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-9364) in projectworlds Online Art Gallery Shop 1.0 can lead to unauthorized access to sensitive data, including user credentials, customer information, and financial records. The attacker could potentially modify data, escalate privileges, or even take complete control of the application and its underlying database. The NVD lists the CVSS v3.1 score as 7.3 HIGH. Given that a public exploit is available, the risk of widespread exploitation is elevated.

## Recommendation

*   Apply input validation and sanitization to the `social_linked` parameter in `/admin/adminHome.php` to prevent SQL injection attacks.
*   Deploy the provided Sigma rules to detect potential exploitation attempts targeting CVE-2026-9364 in web server logs.
*   Monitor web server logs for suspicious activity, such as requests containing SQL injection payloads, based on the provided Sigma rules.
*   Consider using a web application firewall (WAF) to filter out malicious requests and protect against SQL injection attacks.
