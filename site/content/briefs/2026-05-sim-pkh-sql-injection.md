---
title: SIM-PKH 2.4.1 SQL Injection Vulnerability (CVE-2018-25410)
slug: 2026-05-sim-pkh-sql-injection
description: SIM-PKH version 2.4.1 is vulnerable to SQL injection (CVE-2018-25410), allowing an authenticated attacker to execute arbitrary SQL queries by injecting malicious code through the 'id' parameter via a crafted GET request, potentially leading to database information disclosure.
date: "2026-05-30T16:19:04Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - sql-injection
  - cve
  - web-application
vendors:
  - SIM-PKH
products:
  - SIM-PKH 2.4.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25410
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25410
rules:
  - title: Detect CVE-2018-25410 Exploitation Attempt — SIM-PKH SQL Injection
    description: Detects CVE-2018-25410 exploitation attempt — SQL injection in SIM-PKH 2.4.1 via suspicious GET request to /admin/media.php with SQL UNION statements
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

SIM-PKH 2.4.1 is susceptible to SQL injection vulnerability (CVE-2018-25410). An authenticated attacker can exploit this vulnerability by injecting malicious SQL code into the 'id' parameter of a GET request. The vulnerability exists in the `/admin/media.php` endpoint, specifically when the `module` parameter is set to `pengurus` and the `act` parameter is set to `editpengurus`. A successful exploit enables the attacker to execute arbitrary SQL queries, potentially leading to the extraction of sensitive database information, including usernames, database names, and version details. This vulnerability poses a significant risk to the confidentiality and integrity of the SIM-PKH application and its underlying database.

## Attack Chain

1.  The attacker authenticates to the SIM-PKH application.
2.  The attacker crafts a malicious GET request targeting `/admin/media.php`.
3.  The attacker sets the `module` parameter to `pengurus` and the `act` parameter to `editpengurus`.
4.  The attacker injects malicious SQL code into the `id` parameter, using SQL UNION statements.
5.  The attacker sends the crafted GET request to the server.
6.  The server processes the request and executes the injected SQL query against the database.
7.  The database returns the results of the injected SQL query to the server.
8.  The server displays the extracted database information, including usernames, database names, and version details, to the attacker.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2018-25410) in SIM-PKH 2.4.1 allows an attacker to extract sensitive information from the database. This may include usernames, passwords, database names, version details, and other confidential data. The compromise of this information can lead to unauthorized access, data breaches, and further attacks against the application and its users. The CVSS v3.1 base score for this vulnerability is 7.1, indicating a high severity.

## Recommendation

*   Apply available patches or upgrade to a secure version of SIM-PKH to remediate CVE-2018-25410.
*   Deploy the Sigma rule "Detect CVE-2018-25410 Exploitation Attempt — SIM-PKH SQL Injection" to identify potential exploitation attempts in web server logs.
*   Review and harden database access controls to limit the impact of potential SQL injection attacks.
