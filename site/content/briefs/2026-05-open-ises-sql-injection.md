---
title: Open ISES Tickets SQL Injection Vulnerability (CVE-2026-48231)
slug: 2026-05-open-ises-sql-injection
description: Open ISES Tickets before version 3.44.2 is vulnerable to SQL injection (CVE-2026-48231) in tables.php due to unsanitized concatenation of POST parameters, allowing authenticated attackers to manipulate database queries.
date: "2026-05-21T18:18:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2026-48231
  - web-application
vendors:
  - Open ISES
products:
  - Tickets
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-48231
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48231
  - https://github.com/openises/tickets/commit/ecfeb406a016766cae81c749e14b5145a9f2dbff
  - https://github.com/openises/tickets/releases/tag/v3.44.2
  - https://www.vulncheck.com/advisories/open-ises-tickets-sql-injection-via-tables-php-multiple-parameters
rules:
  - title: Detect CVE-2026-48231 Exploitation — SQL Injection Attempt in tables.php
    description: Detects CVE-2026-48231 exploitation — suspicious POST requests to tables.php with SQL injection patterns in tablename, indexname, or sortby parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-48231 Exploitation — SQL Injection Attempt via Multiple Parameters
    description: Detects CVE-2026-48231 exploitation — SQL injection attempt by detecting concatenated parameters in the request.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Open ISES Tickets, a web-based ticketing system, is vulnerable to SQL injection in versions prior to 3.44.2. The vulnerability, identified as CVE-2026-48231, resides in the `tables.php` file. Multiple POST parameters (`tablename`, `indexname`, `sortby`) are concatenated without proper sanitization when constructing SQL queries. This allows authenticated attackers, possessing valid user credentials, to inject malicious SQL code into dynamically generated SELECT, UPDATE, or DELETE statements. Successful exploitation can lead to unauthorized data access, modification, or complete database destruction. This vulnerability was reported by VulnCheck and patched in version 3.44.2.

## Attack Chain

1.  Attacker authenticates to the Open ISES Tickets application with valid credentials.
2.  Attacker crafts a malicious HTTP POST request to `tables.php`.
3.  The POST request includes crafted values for the `tablename`, `indexname`, and `sortby` parameters containing SQL injection payloads.
4.  The application concatenates these unsanitized POST parameters into a dynamically constructed SQL query.
5.  The injected SQL code alters the intended query semantics.
6.  The malicious SQL query is executed against the database.
7.  The attacker gains unauthorized access to sensitive data.
8.  The attacker modifies or deletes data within the database, causing data corruption or service disruption.

## Impact

Successful exploitation of CVE-2026-48231 allows attackers to read, modify, or destroy sensitive data within the Open ISES Tickets database. The vulnerability requires authentication, limiting the scope to users with valid credentials. However, the potential impact includes unauthorized access to confidential ticket information, modification of user accounts, and complete database compromise, leading to significant data loss and operational disruption. The CVSS v3.1 base score is 7.1, indicating a high severity vulnerability.

## Recommendation

*   Upgrade Open ISES Tickets to version 3.44.2 or later to remediate CVE-2026-48231.
*   Apply the patch referenced in the [Open ISES Tickets commit](https://github.com/openises/tickets/commit/ecfeb406a016766cae81c749e14b5145a9f2dbff) to address the SQL injection vulnerability.
*   Monitor web server logs for suspicious POST requests to `tables.php` containing SQL injection attempts, triggering on `tablename`, `indexname`, or `sortby` parameters, using a rule similar to the example below.
