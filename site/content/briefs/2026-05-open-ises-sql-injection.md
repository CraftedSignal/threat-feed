---
title: Open ISES Tickets SQL Injection Vulnerability (CVE-2026-48234)
slug: 2026-05-open-ises-sql-injection
description: Open ISES Tickets before 3.44.2 is vulnerable to SQL injection in portal/ajax/list_requests.php via unsanitized sort and dir GET parameters, allowing authenticated attackers to read, modify, or destroy database contents.
date: "2026-05-21T18:19:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2026-48234
  - web-application
vendors:
  - Open ISES
products:
  - Tickets
  - Tickets <= 3.44.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1213
    technique_name: Data from Information Repository
cves:
  - id: CVE-2026-48234
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48234
  - https://github.com/openises/tickets/commit/ecfeb406a016766cae81c749e14b5145a9f2dbff
  - https://github.com/openises/tickets/releases/tag/v3.44.2
  - https://www.vulncheck.com/advisories/open-ises-tickets-sql-injection-via-portal-ajax-list-requests-php-sort-and-dir-parameters
rules:
  - title: Detects CVE-2026-48234 Exploitation -- Open ISES Tickets SQL Injection
    description: Detects CVE-2026-48234 exploitation -- SQL injection attempts in Open ISES Tickets via the sort and dir parameters in portal/ajax/list_requests.php
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1213
    data_sources:
      - webserver
rules_count: 1
---

Open ISES Tickets before version 3.44.2 contains a SQL injection vulnerability in the `portal/ajax/list_requests.php` script. The vulnerability exists because the `sort` and `dir` GET parameters are directly concatenated into the `ORDER BY` clause of a SQL `SELECT` statement without proper sanitization. This allows an attacker with valid authentication to manipulate the SQL query. The vulnerability was reported by VulnCheck and patched in version 3.44.2. Successful exploitation could lead to unauthorized data access, modification, or deletion within the Open ISES Tickets database.

## Attack Chain

1. An authenticated attacker identifies the vulnerable `portal/ajax/list_requests.php` endpoint.
2. The attacker crafts a malicious HTTP GET request to `portal/ajax/list_requests.php`.
3. The crafted request includes the `sort` and/or `dir` parameters containing SQL injection payloads such as `id ASC, (SELECT ...)` or similar SQL injection syntax.
4. The Open ISES Tickets application receives the request and concatenates the malicious `sort` and `dir` parameters into the `ORDER BY` clause of a SQL query.
5. The application executes the maliciously crafted SQL query against the database.
6. The injected SQL code executes, potentially allowing the attacker to read sensitive data, modify existing data, or insert new data.
7. The attacker retrieves the results of the injected SQL query, potentially including sensitive information or confirmation of successful data modification.
8. The attacker can then use this vulnerability to extract sensitive information or gain complete control over the database contents.

## Impact

A successful SQL injection attack can have severe consequences. An attacker could potentially read sensitive information from the database, such as usernames, passwords, customer data, or internal system configurations. The attacker can also modify or delete data, leading to data corruption, service disruption, or financial loss. With escalated privileges, the attacker could potentially gain complete control over the Open ISES Tickets system and any associated infrastructure.

## Recommendation

*   Upgrade Open ISES Tickets to version 3.44.2 or later to patch CVE-2026-48234.
*   Deploy the Sigma rule "Detects CVE-2026-48234 Exploitation -- Open ISES Tickets SQL Injection" to your SIEM to detect exploitation attempts.
*   Monitor web server logs for suspicious requests to `portal/ajax/list_requests.php` containing SQL injection payloads in the `sort` or `dir` parameters (see IOC section for examples).
*   Implement input validation and sanitization on all user-supplied input, especially in database queries, to prevent future SQL injection vulnerabilities.
