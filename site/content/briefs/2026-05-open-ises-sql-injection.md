---
title: Open ISES Tickets SQL Injection Vulnerability (CVE-2026-48233)
slug: 2026-05-open-ises-sql-injection
description: Open ISES Tickets before version 3.44.2 is vulnerable to SQL injection via the offset GET parameter in ajax/sit_incidents.php, allowing authenticated attackers to manipulate SQL queries and potentially read, modify, or destroy database contents.
date: "2026-05-21T18:19:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2026-48233
  - web-application
vendors:
  - Open ISES
products:
  - Tickets
  - Tickets before 3.44.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-48233
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48233
  - https://github.com/openises/tickets/commit/ecfeb406a016766cae81c749e14b5145a9f2dbff
  - https://github.com/openises/tickets/releases/tag/v3.44.2
  - https://www.vulncheck.com/advisories/open-ises-tickets-sql-injection-via-ajax-sit-incidents-php-offset-parameter
rules:
  - title: Detects CVE-2026-48233 Exploitation — Open ISES Tickets SQL Injection via offset Parameter
    description: Detects CVE-2026-48233 exploitation — SQL injection attempts in Open ISES Tickets via the offset parameter in ajax/sit_incidents.php
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-48233 Exploitation — Open ISES Tickets SQL Injection via offset Parameter - No Offset Base
    description: Detects CVE-2026-48233 exploitation — SQL injection attempts in Open ISES Tickets via the offset parameter in ajax/sit_incidents.php when offset does not start from an integer value
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

Open ISES Tickets before version 3.44.2 contains a SQL injection vulnerability identified as CVE-2026-48233. The vulnerability resides in the `ajax/sit_incidents.php` file, where the `offset` GET parameter is directly concatenated into the `LIMIT` clause of a SQL `SELECT` statement without proper sanitization. This allows authenticated attackers to inject arbitrary SQL code by crafting malicious requests. Successful exploitation could lead to unauthorized data access, modification, or deletion within the Open ISES Tickets database. The vulnerability was patched in version 3.44.2.

## Attack Chain

1. An authenticated attacker logs into the Open ISES Tickets application.
2. The attacker crafts a malicious HTTP GET request targeting `ajax/sit_incidents.php`.
3. The crafted request includes a modified `offset` parameter containing SQL injection payloads, such as `' OR '1'='1`.
4. The application concatenates the unsanitized `offset` parameter into the `LIMIT` clause of a SQL `SELECT` statement.
5. The injected SQL code alters the query's intended logic, potentially bypassing intended data filtering or access controls.
6. The database executes the modified SQL query, potentially revealing sensitive data or allowing unauthorized data manipulation.
7. The attacker receives the results of the injected SQL query in the HTTP response, confirming the successful SQL injection.
8. The attacker can then leverage the SQL injection vulnerability to read, modify, or destroy database contents.

## Impact

Successful exploitation of this vulnerability could lead to severe consequences, including unauthorized access to sensitive information, data breaches, data manipulation, and potential disruption of Open ISES Tickets service. Since the application is used for ticketing, this could impact incident response and service management workflows. The vulnerability affects all deployments of Open ISES Tickets prior to version 3.44.2.

## Recommendation

*   Upgrade Open ISES Tickets to version 3.44.2 or later to patch the vulnerability.
*   Deploy the Sigma rule to detect potential SQL injection attempts targeting `ajax/sit_incidents.php` using the `offset` parameter.
*   Implement input validation and sanitization for all user-supplied input, especially for parameters used in SQL queries, to prevent SQL injection vulnerabilities.
