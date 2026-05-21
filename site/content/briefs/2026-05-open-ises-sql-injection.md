---
title: Open ISES Tickets SQL Injection Vulnerability (CVE-2026-48240)
slug: 2026-05-open-ises-sql-injection
description: Open ISES Tickets before version 3.44.2 is vulnerable to SQL injection in ajax/statistics.php via the tick_id and f_tick_id POST parameters, allowing authenticated attackers to manipulate SQL queries and potentially read, modify, or destroy database contents.
date: "2026-05-21T18:20:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2026-48240
  - web-application
vendors:
  - Open ISES
products:
  - Tickets (< 3.44.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-48240
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48240
  - https://github.com/openises/tickets/commit/ecfeb406a016766cae81c749e14b5145a9f2dbff
  - https://github.com/openises/tickets/releases/tag/v3.44.2
  - https://www.vulncheck.com/advisories/open-ises-tickets-sql-injection-via-ajax-statistics-php-tick-id-and-f-tick-id-parameters
rules:
  - title: Detects CVE-2026-48240 Exploitation — Open ISES Tickets SQL Injection Attempt
    description: Detects CVE-2026-48240 exploitation attempt in Open ISES Tickets by identifying suspicious POST requests to ajax/statistics.php with SQL injection payloads in tick_id or f_tick_id parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-48240 Exploitation — Open ISES Tickets SQL Injection Error Responses
    description: Detects CVE-2026-48240 exploitation attempt in Open ISES Tickets based on web server error responses following a SQL injection attempt to ajax/statistics.php.
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

Open ISES Tickets before version 3.44.2 is susceptible to a SQL injection vulnerability (CVE-2026-48240) within the `ajax/statistics.php` script. The vulnerability stems from the improper sanitization of the `tick_id` and `f_tick_id` POST parameters. These parameters are directly concatenated into the WHERE clauses of SELECT statements used in statistics rollup queries. An authenticated attacker can exploit this flaw by crafting malicious requests that alter the query's intended semantics, potentially enabling the unauthorized reading, modification, or deletion of sensitive data stored within the database. This issue was reported by VulnCheck and has a CVSS v3.1 base score of 7.1.

## Attack Chain

1.  Attacker authenticates to the Open ISES Tickets application with valid credentials.
2.  Attacker crafts a malicious HTTP POST request targeting `ajax/statistics.php`.
3.  The POST request includes the `tick_id` or `f_tick_id` parameter containing a SQL injection payload.
4.  The application unsafely concatenates the attacker-controlled parameters into the SQL query's WHERE clause.
5.  The malicious SQL query executes against the database, potentially altering data selection, modification, or deletion.
6.  The application returns a potentially modified or erroneous statistics rollup result based on the injected SQL.
7.  Attacker analyzes the response to refine and escalate the SQL injection attack.
8.  Attacker leverages the successful SQL injection to read sensitive database contents or perform unauthorized data manipulation, potentially compromising the entire application.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-48240) could allow an attacker to read sensitive information from the Open ISES Tickets database, potentially including user credentials, ticket details, and other confidential data. The attacker may also be able to modify or delete data, leading to data corruption or denial of service. Given the high CVSS score of 7.1, this vulnerability poses a significant risk to the confidentiality and integrity of the application and its data.

## Recommendation

*   Upgrade Open ISES Tickets to version 3.44.2 or later to patch CVE-2026-48240 (see References).
*   Deploy the Sigma rules provided below to detect potential exploitation attempts targeting the vulnerable `ajax/statistics.php` endpoint.
*   Implement input validation and sanitization for the `tick_id` and `f_tick_id` POST parameters in `ajax/statistics.php` to prevent SQL injection attacks.
*   Review and restrict database access privileges for the Open ISES Tickets application to minimize the impact of successful SQL injection attacks.
