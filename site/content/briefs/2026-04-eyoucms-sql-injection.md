---
title: EyouCMS SQL Injection Vulnerability (CVE-2026-7389)
slug: 2026-04-eyoucms-sql-injection
description: A remote SQL injection vulnerability (CVE-2026-7389) exists in EyouCMS versions up to 1.7.9 due to improper handling of the 'sort_asc' argument in the GetSortData function, potentially allowing attackers to execute arbitrary SQL commands.
date: "2026-04-29T16:16:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2026-7389
  - web-application
products:
  - EyouCMS (<= 1.7.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7389
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7389
  - https://gitee.com/weng_xianhu/eyoucms/issues/IILFPE
  - https://vuldb.com/vuln/360114
rules:
  - title: Detect EyouCMS SQL Injection via sort_asc Parameter
    description: Detects potential SQL injection attempts in EyouCMS by monitoring requests to application/common.php with suspicious sort_asc parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - sql_injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect EyouCMS SQL Injection via sort_asc Parameter (POST)
    description: Detects potential SQL injection attempts in EyouCMS by monitoring requests to application/common.php with suspicious sort_asc parameters in POST requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - sql_injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A security vulnerability, CVE-2026-7389, has been identified in EyouCMS, specifically affecting versions up to 1.7.9. This vulnerability stems from insufficient sanitization of user-supplied input passed to the `sort_asc` argument of the `GetSortData` function located in the `application/common.php` file. An unauthenticated, remote attacker can exploit this vulnerability to inject malicious SQL queries into the application. Publicly available exploits increase the risk of widespread exploitation. The project maintainers were notified but have not yet addressed the issue, making timely detection and mitigation critical for defenders.

## Attack Chain

1.  The attacker identifies an EyouCMS instance running a vulnerable version (<= 1.7.9).
2.  The attacker crafts a malicious HTTP request targeting the `GetSortData` function within `application/common.php`.
3.  The crafted request includes a manipulated `sort_asc` argument containing a SQL injection payload.
4.  The application processes the request without proper sanitization of the `sort_asc` parameter.
5.  The unsanitized input is incorporated into a SQL query executed by the application.
6.  The injected SQL code modifies the query logic, allowing the attacker to potentially bypass authentication.
7.  The attacker can read sensitive data from the database, such as user credentials or configuration information.
8.  The attacker may escalate privileges or gain complete control of the database server, leading to data exfiltration or service disruption.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-7389) could allow an attacker to read, modify, or delete sensitive data stored in the EyouCMS database. This could include user credentials, financial information, or other confidential data. Since an exploit is publicly available, organizations using vulnerable versions of EyouCMS are at increased risk of compromise, potentially leading to data breaches, financial loss, and reputational damage.

## Recommendation

*   Deploy the Sigma rule `Detect EyouCMS SQL Injection via sort_asc Parameter` to identify exploitation attempts in web server logs.
*   Inspect web server logs for suspicious requests targeting `application/common.php` with unusual parameters in the `sort_asc` argument based on the Sigma rule.
*   Apply input validation and sanitization to the `sort_asc` parameter in the `GetSortData` function to prevent SQL injection.
