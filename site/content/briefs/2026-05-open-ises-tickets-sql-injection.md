---
title: Open ISES Tickets SQL Injection Vulnerability (CVE-2026-48238)
slug: 2026-05-open-ises-tickets-sql-injection
description: Open ISES Tickets before version 3.44.2 is vulnerable to SQL injection (CVE-2026-48238) because the id GET parameter in ajax/mobile_main.php is concatenated into the WHERE clause of a SELECT statement without sanitization, allowing authenticated attackers to craft requests that can read, modify, or destroy database contents.
date: "2026-05-21T18:20:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - sql-injection
  - web-application
vendors:
  - Open ISES
products:
  - Tickets < 3.44.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-48238
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48238
  - https://github.com/openises/tickets/commit/ecfeb406a016766cae81c749e14b5145a9f2dbff
  - https://github.com/openises/tickets/releases/tag/v3.44.2
  - https://www.vulncheck.com/advisories/open-ises-tickets-sql-injection-via-ajax-mobile-main-php-id-parameter
rules:
  - title: Detect SQL Injection Attempts in Open ISES Tickets
    description: Detects CVE-2026-48238 exploitation — SQL injection attempts targeting the id parameter in Open ISES Tickets ajax/mobile_main.php
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect SQL Injection Error Messages in Open ISES Tickets
    description: Detects potential CVE-2026-48238 exploitation attempts by monitoring for SQL error messages in the web server logs after requests to the vulnerable endpoint.
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

Open ISES Tickets before version 3.44.2 is susceptible to SQL injection in the ajax/mobile_main.php component. The vulnerability stems from the insecure handling of the `id` GET parameter. Specifically, this parameter is directly concatenated into the WHERE clause of a SELECT statement without proper sanitization or parameterization. This allows an authenticated attacker to manipulate the SQL query and potentially read, modify, or delete sensitive data within the database. This vulnerability was reported on 2026-05-21 and assigned CVE-2026-48238. Exploitation requires authentication, however, the impact can be significant, leading to data breaches or complete system compromise.

## Attack Chain

1.  An authenticated attacker identifies the vulnerable endpoint `ajax/mobile_main.php`.
2.  The attacker crafts a malicious HTTP GET request targeting `ajax/mobile_main.php`.
3.  The crafted GET request includes the `id` parameter with a SQL injection payload.
4.  The server-side application concatenates the unsanitized `id` parameter into the SQL query.
5.  The malicious SQL query is executed against the database.
6.  The attacker can read sensitive data from the database by using `UNION SELECT` to extract data from other tables.
7.  Alternatively, the attacker modifies data using `UPDATE` statements within the injected SQL.
8.  The attacker can potentially gain full control over the application data, leading to complete compromise.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-48238) can allow an attacker to read, modify, or destroy data within the Open ISES Tickets database. This can lead to sensitive information disclosure, data corruption, or denial of service. Given a CVSS base score of 7.1, the risk is considerable, especially if the targeted Open ISES Tickets instance contains sensitive information or is critical to business operations.

## Recommendation

*   Upgrade Open ISES Tickets to version 3.44.2 or later to patch the SQL injection vulnerability (CVE-2026-48238) as recommended by the vendor.
*   Deploy the Sigma rule `Detect SQL Injection Attempts in Open ISES Tickets` to detect exploitation attempts targeting the vulnerable endpoint.
*   Monitor web server logs for suspicious GET requests to `ajax/mobile_main.php` containing SQL injection payloads, specifically looking for SQL keywords or syntax in the `id` parameter.
