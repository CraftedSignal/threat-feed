---
title: Open ISES Tickets SQL Injection Vulnerability (CVE-2026-48239)
slug: 2026-05-open-ises-sql-injection
description: Open ISES Tickets before version 3.44.2 is vulnerable to SQL injection via the tick_id POST parameter in ajax/reports.php, allowing an authenticated attacker to alter query semantics to read, modify, or destroy database contents.
date: "2026-05-21T18:20:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve
  - web-application
vendors:
  - Open ISES
products:
  - Tickets <= 3.44.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-48239
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48239
  - https://github.com/openises/tickets/commit/ecfeb406a016766cae81c749e14b5145a9f2dbff
  - https://github.com/openises/tickets/releases/tag/v3.44.2
  - https://www.vulncheck.com/advisories/open-ises-tickets-sql-injection-via-ajax-reports-php-tick-id-parameter
rules:
  - title: Detect SQL Injection in Open ISES Tickets
    description: Detects CVE-2026-48239 exploitation - SQL injection attempts in Open ISES Tickets ajax/reports.php via tick_id parameter
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

Open ISES Tickets before version 3.44.2 contains a SQL injection vulnerability identified as CVE-2026-48239. The vulnerability exists within the `ajax/reports.php` file, where the `tick_id` POST parameter is unsafely concatenated into the WHERE clause of SELECT statements in the incidents summary report. An authenticated attacker can exploit this flaw to inject arbitrary SQL code into the query, potentially leading to unauthorized data access, modification, or deletion. Successful exploitation requires an attacker to have valid user credentials and the ability to make HTTP POST requests to the affected endpoint.

## Attack Chain

1. An attacker authenticates to the Open ISES Tickets application with valid credentials.
2. The attacker crafts a malicious HTTP POST request targeting the `ajax/reports.php` endpoint.
3. The POST request includes a `tick_id` parameter containing a SQL injection payload.
4. The application receives the request and concatenates the `tick_id` value into a SQL query without proper sanitization.
5. The injected SQL code alters the query's intended logic.
6. The database executes the malicious SQL query.
7. The attacker gains unauthorized access to sensitive data, modifies existing data, or deletes data from the database.
8. The attacker can potentially escalate privileges within the application or gain control of the underlying server, depending on the database configuration and the attacker's skill.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-48239) can have severe consequences, including unauthorized access to sensitive ticket data, modification or deletion of incident reports, and potential compromise of the entire Open ISES Tickets application. The CVSS v3.1 base score is 7.1, highlighting the high risk associated with this vulnerability. Organizations using affected versions of Open ISES Tickets are at risk of data breaches, data manipulation, and service disruption.

## Recommendation

*   Upgrade Open ISES Tickets to version 3.44.2 or later to patch the SQL injection vulnerability (CVE-2026-48239) as mentioned in the advisory.
*   Deploy the Sigma rule `Detect SQL Injection in Open ISES Tickets` to identify potentially malicious requests targeting the vulnerable `ajax/reports.php` endpoint.
*   Implement input validation and sanitization measures on all user-supplied data, especially within SQL queries, to prevent future SQL injection vulnerabilities.
