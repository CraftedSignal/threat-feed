---
title: Open ISES Tickets SQL Injection Vulnerability (CVE-2026-48232)
slug: 2026-05-open-ises-tickets-sql-injection
description: Open ISES Tickets before version 3.44.2 is vulnerable to SQL injection in the ajax/fullsit_incidents.php file via the offset GET parameter, allowing authenticated attackers to manipulate SQL queries.
date: "2026-05-21T18:19:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2026-48232
  - web-application
vendors:
  - Open ISES
products:
  - Tickets
cves:
  - id: CVE-2026-48232
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48232
  - https://github.com/openises/tickets/commit/ecfeb406a016766cae81c749e14b5145a9f2dbff
  - https://github.com/openises/tickets/releases/tag/v3.44.2
  - https://www.vulncheck.com/advisories/open-ises-tickets-sql-injection-via-ajax-fullsit-incidents-php-offset-parameter
rules:
  - title: Detect SQL Injection Attempts in Open ISES Tickets via Offset Parameter
    description: Detects SQL injection attempts in Open ISES Tickets by monitoring requests to ajax/fullsit_incidents.php with a suspicious offset parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect potentially successful SQL injection in Open ISES Tickets
    description: Detects potentially successful SQL injection in Open ISES Tickets based on HTTP response codes after a suspicious offset parameter is used.
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

Open ISES Tickets, a web-based ticketing system, is vulnerable to SQL injection (CVE-2026-48232) in versions prior to 3.44.2. The vulnerability lies within the `ajax/fullsit_incidents.php` script, where the `offset` GET parameter is directly incorporated into the `LIMIT` clause of a SQL `SELECT` statement without proper sanitization. This flaw allows authenticated attackers to inject malicious SQL code by crafting specific HTTP GET requests. Successful exploitation enables attackers to potentially read, modify, or even destroy database contents. Defenders should upgrade to version 3.44.2 or apply provided patches as soon as possible.

## Attack Chain

1. An authenticated attacker logs into the Open ISES Tickets application.
2. The attacker crafts a malicious HTTP GET request targeting the `/ajax/fullsit_incidents.php` endpoint.
3. The malicious request includes the `offset` parameter containing SQL injection payloads. For example: `offset=1 UNION SELECT password FROM users--`.
4. The application server receives the request and executes the vulnerable SQL query against the database, incorporating the attacker-supplied `offset` value.
5. The injected SQL code manipulates the original query, potentially extracting sensitive data like user passwords.
6. The database server executes the modified SQL query and returns the results to the application.
7. The application displays the results, potentially revealing sensitive information to the attacker.
8. The attacker uses extracted credentials or data to further compromise the application or gain access to other systems.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-48232) can lead to complete database compromise, including unauthorized data access, modification, and deletion. An attacker can potentially steal sensitive information such as user credentials, customer data, or proprietary business information. The number of victims will depend on the specific installation base of Open ISES Tickets. Affected sectors would likely include any organization using Open ISES Tickets for their IT support or help desk operations.

## Recommendation

*   Upgrade Open ISES Tickets to version 3.44.2 or later to remediate CVE-2026-48232, as mentioned in the overview.
*   Deploy the Sigma rule "Detect SQL Injection Attempts in Open ISES Tickets via Offset Parameter" to identify malicious requests targeting the `/ajax/fullsit_incidents.php` endpoint.
*   Monitor web server logs for unusual activity and SQL injection attempts targeting the `/ajax/fullsit_incidents.php` endpoint, as described in the Attack Chain.
*   Implement input validation and sanitization on all user-supplied data, including the `offset` parameter in `ajax/fullsit_incidents.php`, to prevent future SQL injection vulnerabilities.
