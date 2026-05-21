---
title: Open ISES Tickets SQL Injection Vulnerability (CVE-2026-48237)
slug: 2026-05-open-ises-sql-injection
description: Open ISES Tickets before 3.44.2 is vulnerable to SQL injection via the frm_ticket_id and frm_resp_id POST parameters in message.php, allowing authenticated attackers to manipulate database queries.
date: "2026-05-21T18:20:06Z"
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
  - openises
products:
  - Tickets
  - Tickets <= 3.44.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-48237
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48237
  - https://github.com/openises/tickets/commit/ecfeb406a016766cae81c749e14b5145a9f2dbff
  - https://github.com/openises/tickets/releases/tag/v3.44.2
  - https://www.vulncheck.com/advisories/open-ises-tickets-sql-injection-via-message-php-frm-ticket-id-and-frm-resp-id-parameters
rules:
  - title: Detect CVE-2026-48237 Exploitation Attempt via message.php
    description: Detects CVE-2026-48237 exploitation — HTTP POST to message.php with SQL injection attempts in frm_ticket_id or frm_resp_id parameters
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
  - title: Detect Potential SQL Injection in POST Request
    description: Detects a POST request containing potential SQL injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
rules_count: 2
---

Open ISES Tickets before version 3.44.2 is susceptible to SQL injection attacks. The vulnerability resides in the `message.php` file, where the `frm_ticket_id` and `frm_resp_id` POST parameters are directly concatenated into the WHERE clauses of SELECT and UPDATE SQL statements. This improper sanitization allows authenticated attackers to inject arbitrary SQL code by crafting malicious requests. Successful exploitation can lead to unauthorized data access, modification, or deletion within the Open ISES Tickets database. This vulnerability was reported by VulnCheck and assigned CVE-2026-48237.

## Attack Chain

1.  An authenticated attacker identifies the vulnerable `message.php` endpoint.
2.  The attacker crafts a malicious HTTP POST request targeting `message.php`.
3.  The crafted POST request includes SQL injection payloads within the `frm_ticket_id` and/or `frm_resp_id` parameters.
4.  The server-side application (`message.php`) receives the request and concatenates the unsanitized parameters into SQL queries.
5.  The modified SQL query is executed against the Open ISES Tickets database.
6.  The injected SQL code alters the query's intended logic, potentially allowing the attacker to bypass authentication checks, extract sensitive data (e.g., usernames, passwords, ticket details), modify existing records, or even drop tables.
7.  The database server processes the injected SQL commands.
8.  The attacker gains unauthorized access to the database or manipulates data according to the injected SQL code.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-48237) can lead to severe consequences, including unauthorized access to sensitive ticket information, modification or deletion of critical data, and potential compromise of the entire Open ISES Tickets system. Authenticated attackers could exploit this to escalate privileges or disrupt service availability.

## Recommendation

*   Upgrade Open ISES Tickets to version 3.44.2 or later to patch CVE-2026-48237 as recommended by the vendor.
*   Deploy the Sigma rule "Detect CVE-2026-48237 Exploitation Attempt via message.php" to detect suspicious POST requests containing SQL injection payloads in the `frm_ticket_id` and `frm_resp_id` parameters.
*   Implement input validation and sanitization for all user-supplied data, especially within SQL queries.
*   Monitor web server logs for unusual activity and potential SQL injection attempts targeting `message.php`.
