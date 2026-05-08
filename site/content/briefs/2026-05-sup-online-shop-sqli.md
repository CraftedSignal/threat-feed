---
title: SourceCodester SUP Online Shopping SQL Injection Vulnerability (CVE-2026-8130)
slug: 2026-05-sup-online-shop-sqli
description: SourceCodester SUP Online Shopping 1.0 is vulnerable to SQL injection via the 'seenid' parameter in /admin/message.php, allowing remote attackers to execute arbitrary SQL commands; exploit code is publicly available.
date: "2026-05-08T04:16:24Z"
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
  - SourceCodester
products:
  - SUP Online Shopping 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-8130
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8130
  - https://github.com/redshadowword-cell/CVE/issues/11
  - https://vuldb.com/vuln/361920
rules:
  - title: Detect SQL Injection Attempt in SUP Online Shopping
    description: Detects potential SQL injection attempts targeting the seenid parameter in SourceCodester SUP Online Shopping's /admin/message.php file, indicative of CVE-2026-8130 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
  - title: Detect SQL Error Messages
    description: Detects SQL error messages returned by the web server, which can indicate SQL injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
rules_count: 2
---

A SQL injection vulnerability, identified as CVE-2026-8130, affects SourceCodester SUP Online Shopping version 1.0. The vulnerability resides within the `/admin/message.php` file and is triggered by manipulating the `seenid` argument. This flaw allows a remote attacker to inject and execute arbitrary SQL commands on the underlying database. The existence of publicly available exploit code increases the risk of exploitation, making it easier for threat actors to compromise vulnerable systems. Due to the sensitive nature of online shopping applications, a successful exploit could lead to data breaches, financial fraud, or unauthorized access to administrative functions.

## Attack Chain

1.  An attacker identifies a vulnerable instance of SourceCodester SUP Online Shopping 1.0.
2.  The attacker crafts a malicious HTTP request targeting the `/admin/message.php` endpoint.
3.  The crafted request includes a SQL injection payload within the `seenid` parameter.
4.  The application fails to properly sanitize or validate the `seenid` input.
5.  The malicious SQL query is executed against the database.
6.  The attacker retrieves sensitive data, such as user credentials or financial information.
7.  Alternatively, the attacker modifies data within the database to escalate privileges or manipulate transactions.
8.  The attacker gains unauthorized access to administrative functions or exfiltrates sensitive data.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to a range of damaging outcomes. Attackers could potentially gain unauthorized access to sensitive customer data, including personal information, payment details, and order history. This could result in financial losses for both the business and its customers, as well as reputational damage. Furthermore, attackers might be able to manipulate product pricing, user accounts, or even gain complete control over the online store, leading to significant disruption and financial loss.

## Recommendation

*   Apply input validation and sanitization to all user-supplied input, especially the `seenid` parameter in `/admin/message.php`, to prevent SQL injection attacks as described in CVE-2026-8130.
*   Deploy the Sigma rule `Detect SQL Injection Attempt in SUP Online Shopping` to detect potential exploitation attempts.
*   Review and harden database access controls to minimize the impact of successful SQL injection attacks.
