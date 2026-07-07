---
title: CVE-2026-14653 - SourceCodester Simple and Nice Shopping Cart Script SQL Injection
slug: 2026-07-sourcecodester-sqli
description: An SQL injection vulnerability (CVE-2026-14653) in SourceCodester Simple and Nice Shopping Cart Script 1.0's `/admin/mensproductdeletequery.php` via the `user_id` argument allows remote attackers to exfiltrate or manipulate database contents, with a public exploit available.
date: "2026-07-04T21:19:56Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - sql-injection
  - web-vulnerability
  - cve
  - web-application
vendors:
  - SourceCodester
products:
  - Simple and Nice Shopping Cart Script 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote exploitation of the attack is possible.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1537
    technique_name: Data from Information Repositories
    evidence: This manipulation of the argument user_id causes sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-14653
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14653
  - https://github.com/Yuesswor/cve/issues/3
  - https://vuldb.com/cve/CVE-2026-14653
  - https://vuldb.com/submit/846701
  - https://vuldb.com/vuln/376166
  - https://vuldb.com/vuln/376166/cti
  - https://www.sourcecodester.com/
rules:
  - title: Detect CVE-2026-14653 Exploitation - SQL Injection via mensproductdeletequery.php
    description: Detects CVE-2026-14653 exploitation — An SQL Injection vulnerability in SourceCodester Simple and Nice Shopping Cart Script 1.0, targeting the `/admin/mensproductdeletequery.php` endpoint via the `user_id` parameter.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1537
    data_sources:
      - webserver
rules_count: 1
---

A critical SQL injection vulnerability, tracked as CVE-2026-14653, has been identified in SourceCodester Simple and Nice Shopping Cart Script version 1.0. This flaw specifically affects the `user_id` argument within the `/admin/mensproductdeletequery.php` file, enabling remote attackers to bypass authentication and execute arbitrary SQL commands against the backend database. The vulnerability allows for unauthorized data access, modification, or deletion, posing a significant risk of data breach or system compromise. The exploit for this vulnerability has been publicly disclosed, increasing the likelihood of active exploitation by malicious actors seeking to target vulnerable instances of the application. Defenders should prioritize patching and monitoring for exploitation attempts.

## Attack Chain

1. An attacker identifies a vulnerable instance of SourceCodester Simple and Nice Shopping Cart Script 1.0 running a web server.
2. The attacker crafts a malicious HTTP GET request targeting the `/admin/mensproductdeletequery.php` endpoint.
3. The request includes an SQL injection payload within the `user_id` parameter (e.g., `user_id=1%20UNION%20SELECT%20user,password%20FROM%20users--`).
4. The vulnerable application processes the `user_id` parameter without proper sanitization, leading to the execution of the attacker's SQL query.
5. The backend database executes the malicious query, which could be designed to dump database contents, modify records, or create new administrative users.
6. The application returns the results of the malicious query in its HTTP response, allowing the attacker to exfiltrate sensitive data (e.g., user credentials, product information).

## Impact

Successful exploitation of CVE-2026-14653 allows attackers to gain unauthorized access to the application's database, leading to potential data exfiltration, data manipulation, or complete compromise of the application's backend. The CVSS v3.1 base score of 7.3 (High) indicates significant confidentiality, integrity, and availability impacts. Given the public disclosure of an exploit, vulnerable organizations face an elevated risk of immediate exploitation, potentially leading to financial loss, reputational damage, and regulatory penalties due to data breaches.

## Recommendation

*   Immediately apply the vendor-provided patch or update for SourceCodester Simple and Nice Shopping Cart Script 1.0 to address CVE-2026-14653.
*   Deploy the Sigma rule "Detect CVE-2026-14653 Exploitation - SQL Injection via mensproductdeletequery.php" to your SIEM and tune for your environment to detect exploitation attempts.
*   Monitor web server access logs for requests to `/admin/mensproductdeletequery.php` containing suspicious characters or SQL keywords in the `user_id` parameter.
