---
title: Open ISES Tickets Hardcoded Database Credentials Vulnerability
slug: 2026-05-open-ises-hardcoded-credentials
description: Open ISES Tickets before version 3.44.2 contains hardcoded MySQL database connection credentials in import_mdb.php, allowing unauthorized database access.
date: "2026-05-21T18:21:14Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve-2026-48242
  - hardcoded-credentials
  - database-access
vendors:
  - Open ISES
products:
  - Tickets
  - Tickets < 3.44.2
cves:
  - id: CVE-2026-48242
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-48242
  - https://github.com/openises/tickets/commit/ecfeb406a016766cae81c749e14b5145a9f2dbff
  - https://github.com/openises/tickets/releases/tag/v3.44.2
  - https://www.vulncheck.com/advisories/open-ises-tickets-hardcoded-mysql-credentials-in-import-mdb-php
rules:
  - title: Detect MySQL Login using Default Credentials
    description: Detects potential MySQL login attempts using default credentials after CVE-2026-48242.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - database
      - mysql
  - title: Detect Access to import_mdb.php
    description: Detects access to the vulnerable import_mdb.php file, potentially indicating exploitation of CVE-2026-48242.
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

Open ISES Tickets, a web-based ticketing system, suffers from a critical vulnerability (CVE-2026-48242) affecting versions prior to 3.44.2. The vulnerability stems from hardcoded MySQL database connection credentials (host, username, password, database name) within the `import_mdb.php` file. This file, and the credentials within it, were committed to the public code repository. As a result, anyone with access to the source code can potentially gain unauthorized access to the database server, leading to data breaches, modification, or complete system compromise. This exposure is particularly concerning given that deployed installations may be using the default, now-public, credentials.

## Attack Chain

1. Attacker gains access to the Open ISES Tickets source code repository.
2. Attacker locates the `import_mdb.php` file within the repository.
3. Attacker extracts the hardcoded MySQL database connection credentials from `import_mdb.php`.
4. Attacker uses the obtained credentials to establish a connection to the MySQL database server.
5. Attacker authenticates to the database server using the compromised credentials.
6. Attacker executes arbitrary SQL queries to read sensitive data from the database.
7. Attacker may modify or delete data within the database, leading to data corruption or service disruption.
8. Attacker may escalate privileges within the database server and gain access to other systems or data.

## Impact

Successful exploitation of CVE-2026-48242 can lead to full compromise of the Open ISES Tickets system and its associated data. With a CVSS v3.1 score of 8.1, the vulnerability poses a significant risk. The exposure of database credentials allows attackers to read, modify, or delete sensitive information, potentially affecting all users of the ticketing system. The hardcoded nature of the credentials and public accessibility of the code repository significantly increase the likelihood of exploitation. The number of affected installations is currently unknown.

## Recommendation

*   Upgrade to Open ISES Tickets version 3.44.2 or later to remove the hardcoded credentials.
*   Deploy the Sigma rule to detect potential database access attempts using default credentials.
*   Review the `import_mdb.php` file in existing installations and verify that the credentials have been changed from the default values.
*   Rotate database credentials for all Open ISES Tickets instances.
