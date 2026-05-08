---
title: SourceCodester SUP Online Shopping SQL Injection Vulnerability (CVE-2026-8128)
slug: 2026-05-sup-online-shop-sqli
description: A SQL injection vulnerability in SourceCodester SUP Online Shopping 1.0 allows a remote attacker to execute arbitrary SQL commands by manipulating the msgid parameter in /admin/viewmsg.php.
date: "2026-05-08T03:16:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - vulnerability
  - webapp
vendors:
  - SourceCodester
products:
  - SUP Online Shopping 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-8128
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8128
  - https://github.com/redshadowword-cell/CVE/issues/9
  - https://vuldb.com/vuln/361918
rules:
  - title: Detect CVE-2026-8128 Exploitation — SQL Injection attempt via /admin/viewmsg.php
    description: Detects CVE-2026-8128 exploitation — HTTP GET request to /admin/viewmsg.php with SQL injection attempt in the msgid parameter
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-8128 Exploitation — SQL Injection attempt via /admin/viewmsg.php (Blind SQLi)
    description: Detects CVE-2026-8128 exploitation — HTTP GET request to /admin/viewmsg.php with SQL injection attempt in the msgid parameter using sleep command
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A SQL injection vulnerability, identified as CVE-2026-8128, affects SourceCodester SUP Online Shopping version 1.0. This vulnerability resides within the `/admin/viewmsg.php` file, specifically in how the application handles the `msgid` argument. An unauthenticated attacker can remotely exploit this flaw to inject malicious SQL code, potentially leading to unauthorized data access, modification, or deletion. The exploit is publicly available, increasing the risk of exploitation. This poses a significant threat to online shopping platforms using the affected version, potentially impacting sensitive customer data and system integrity.

## Attack Chain

1.  An attacker identifies a vulnerable instance of SourceCodester SUP Online Shopping 1.0.
2.  The attacker crafts a malicious HTTP GET request targeting the `/admin/viewmsg.php` file.
3.  The crafted request includes a modified `msgid` parameter containing SQL injection payloads (e.g., `msgid=1' OR '1'='1`).
4.  The application fails to properly sanitize or escape the `msgid` input.
5.  The unsanitized `msgid` value is directly incorporated into an SQL query executed by the application.
6.  The injected SQL code manipulates the query logic, allowing the attacker to bypass authentication or access restricted data.
7.  The attacker retrieves sensitive information from the database (e.g., user credentials, order details).
8.  The attacker could potentially modify or delete data within the database, leading to data corruption or service disruption.

## Impact

Successful exploitation of this SQL injection vulnerability could lead to the unauthorized access of sensitive customer data, including usernames, passwords, addresses, and payment information. Attackers could potentially modify product prices, manipulate orders, or even shut down the online store. Given that the exploit is publicly available, the risk of widespread attacks is elevated. This could lead to significant financial losses, reputational damage, and legal consequences for affected businesses.

## Recommendation

*   Apply appropriate input validation and sanitization techniques to all user-supplied input, especially the `msgid` parameter in `/admin/viewmsg.php`, to mitigate CVE-2026-8128.
*   Deploy the Sigma rule `Detect CVE-2026-8128 Exploitation — SQL Injection attempt via /admin/viewmsg.php` to identify exploitation attempts.
*   Restrict database user permissions to the minimum necessary level to limit the impact of successful SQL injection attacks.
*   Implement a web application firewall (WAF) to filter out malicious requests targeting the vulnerable endpoint `/admin/viewmsg.php`.
