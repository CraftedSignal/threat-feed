---
title: Joomla J2 JOBS 1.3.0 Authenticated SQL Injection Vulnerability (CVE-2020-37226)
slug: 2026-05-joomla-j2-jobs-sql-injection
description: Joomla J2 JOBS 1.3.0 contains an authenticated SQL injection vulnerability (CVE-2020-37226) that allows authenticated attackers to manipulate database queries by injecting SQL code through the 'sortby' parameter via POST requests, potentially leading to sensitive data extraction.
date: "2026-05-13T16:20:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - joomla
  - j2-jobs
  - cve-2020-37226
vendors:
  - Joomla
products:
  - J2 JOBS 1.3.0
  - J2 JOBS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2020-37226
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-37226
  - https://joomsky.com/
  - https://joomsky.com/products/js-jobs-pro.html
  - https://www.exploit-db.com/exploits/48670
  - https://www.vulncheck.com/advisories/joomla-j2-jobs-authenticated-sql-injection-via-sortby-2
rules:
  - title: Detect Joomla J2 JOBS SQL Injection via Sortby Parameter
    description: Detects CVE-2020-37226 exploitation — SQL injection attempts in the 'sortby' parameter of Joomla J2 JOBS POST requests
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Joomla J2 JOBS SQL Error Messages
    description: Detects CVE-2020-37226 exploitation — SQL error messages returned by the server, potentially indicating successful SQL injection
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

Joomla J2 JOBS 1.3.0 is vulnerable to authenticated SQL injection via the 'sortby' parameter (CVE-2020-37226). This vulnerability allows an attacker with valid administrator credentials to inject arbitrary SQL code into database queries. The vulnerability exists in the component responsible for sorting job listings. By sending a specially crafted POST request to the administrator index with a malicious 'sortby' value, an attacker can manipulate the underlying database queries and potentially extract sensitive information. This poses a significant risk to organizations using the vulnerable J2 JOBS component, as it could lead to data breaches, account compromise, or further exploitation of the Joomla application.

## Attack Chain

1.  Attacker authenticates to the Joomla administrator panel.
2.  Attacker identifies the vulnerable J2 JOBS component's index page.
3.  Attacker crafts a malicious POST request targeting the index page.
4.  The POST request includes the 'sortby' parameter with embedded SQL injection payload.
5.  The application fails to properly sanitize or validate the 'sortby' parameter.
6.  The application constructs a SQL query using the unsanitized 'sortby' value.
7.  The injected SQL code is executed by the database server.
8.  Attacker exfiltrates sensitive information extracted from the database.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2020-37226) can result in unauthorized access to sensitive data stored in the Joomla application's database. This may include user credentials, financial information, or other confidential data. The impact can range from data breaches and reputational damage to financial losses and legal repercussions. Organizations using the vulnerable J2 JOBS 1.3.0 component are at risk.

## Recommendation

*   Upgrade to a patched version of J2 JOBS that addresses the SQL injection vulnerability (CVE-2020-37226).
*   Deploy the Sigma rule `Detect Joomla J2 JOBS SQL Injection via Sortby Parameter` to detect exploitation attempts targeting the 'sortby' parameter in POST requests.
*   Monitor web server logs for suspicious POST requests to the Joomla administrator index containing potentially malicious SQL code within the 'sortby' parameter.
*   Implement input validation and sanitization measures on all user-supplied data, including URL parameters and POST request bodies, to prevent SQL injection attacks.
