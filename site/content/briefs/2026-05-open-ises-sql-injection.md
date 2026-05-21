---
title: Open ISES Tickets SQL Injection Vulnerability (CVE-2026-48236)
slug: 2026-05-open-ises-sql-injection
description: Open ISES Tickets before version 3.44.2 contains a SQL injection vulnerability in the db_loader.php component due to unsanitized concatenation of POST parameters into mysqli connection arguments, allowing authenticated attackers to read, modify, or destroy database contents.
date: "2026-05-21T18:19:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2026-48236
  - web-application
vendors:
  - openises
products:
  - Tickets
  - Tickets < 3.44.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-48236
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48236
  - https://github.com/openises/tickets/commit/ecfeb406a016766cae81c749e14b5145a9f2dbff
  - https://github.com/openises/tickets/releases/tag/v3.44.2
  - https://www.vulncheck.com/advisories/open-ises-tickets-sql-injection-via-db-loader-php-multiple-parameters
rules:
  - title: Detect CVE-2026-48236 Exploitation — Open ISES Tickets SQL Injection
    description: Detects CVE-2026-48236 exploitation — SQL injection attempts in Open ISES Tickets via db_loader.php POST requests containing SQL metacharacters in connection parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Open ISES Tickets db_loader.php Access
    description: Detects access to the db_loader.php page in Open ISES Tickets, which may indicate reconnaissance or attempts to exploit CVE-2026-48236.
    platform: sigma
    severity: informational
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
rules_count: 2
---

Open ISES Tickets before version 3.44.2 is vulnerable to SQL injection in the `db_loader.php` file. The vulnerability, identified as CVE-2026-48236, arises from the unsafe concatenation of POST parameters (`ticketsdb`, `ticketshost`, `ticketsuser`, `ticketspassword`) directly into mysqli connection arguments and dynamic SQL queries. This lack of sanitization allows an authenticated attacker to manipulate query semantics, potentially leading to unauthorized access, modification, or deletion of sensitive database information. The vulnerability was reported on 2026-05-21 and patched in version 3.44.2. Successful exploitation could compromise the integrity and confidentiality of the data stored within the Open ISES Tickets database.

## Attack Chain

1. An attacker authenticates to the Open ISES Tickets application.
2. The attacker crafts a malicious HTTP POST request to `db_loader.php`.
3. The POST request includes crafted values in the `ticketsdb`, `ticketshost`, `ticketsuser`, and `ticketspassword` parameters designed to inject SQL code.
4. The `db_loader.php` script concatenates these POST parameters into mysqli connection arguments without proper sanitization.
5. This results in the execution of attacker-controlled SQL queries against the database.
6. The attacker manipulates the query to bypass intended access controls.
7. The attacker extracts sensitive data from the database or modifies existing data.
8. The attacker can potentially escalate privileges or gain complete control over the database.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-48236) can lead to severe consequences, including unauthorized access to sensitive ticket data, modification or deletion of critical information, and potential compromise of the entire Open ISES Tickets system. The vulnerability affects Open ISES Tickets installations prior to version 3.44.2, potentially impacting any organization using this software for issue tracking.

## Recommendation

*   Upgrade Open ISES Tickets to version 3.44.2 or later to patch CVE-2026-48236.
*   Deploy the Sigma rule `Detect CVE-2026-48236 Exploitation — Open ISES Tickets SQL Injection` to detect exploitation attempts.
*   Implement input validation and sanitization on all user-supplied data, especially the `ticketsdb`, `ticketshost`, `ticketsuser`, and `ticketspassword` parameters in `db_loader.php`.
