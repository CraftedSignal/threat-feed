---
title: MGB OpenSource Guestbook Unauthenticated SQL Injection (CVE-2018-25411)
slug: 2026-05-mgb-guestbook-sqli
description: MGB OpenSource Guestbook 0.7.0.2 contains an SQL injection vulnerability (CVE-2018-25411) that allows unauthenticated attackers to execute arbitrary SQL queries by injecting malicious code through the 'id' parameter in GET requests to email.php, potentially leading to sensitive database information disclosure.
date: "2026-05-30T16:19:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2018-25411
  - web-application
vendors:
  - MGB OpenSource
products:
  - Guestbook 0.7.0.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25411
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25411
  - http://www.m-gb.org/
  - https://sourceforge.net/projects/mopzz-gb/files/latest/download
  - https://www.exploit-db.com/exploits/45665
  - https://www.vulncheck.com/advisories/mgb-opensource-guestbook-sql-injection-via-email-php
rules:
  - title: Detect MGB OpenSource Guestbook SQL Injection via email.php
    description: Detects CVE-2018-25411 exploitation — SQL injection attempts in MGB OpenSource Guestbook 0.7.0.2 by detecting suspicious GET requests to email.php with SQL keywords in the id parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect MGB OpenSource Guestbook SQL Injection Error Based
    description: Detects CVE-2018-25411 exploitation — SQL injection attempts in MGB OpenSource Guestbook 0.7.0.2 based on error messages.
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

MGB OpenSource Guestbook version 0.7.0.2 is vulnerable to SQL injection, as identified by CVE-2018-25411. This vulnerability allows unauthenticated attackers to inject malicious SQL code through the 'id' parameter in GET requests sent to the email.php script. Successful exploitation of this vulnerability can allow attackers to extract sensitive data from the guestbook database, including table names, column names, and potentially user data. This can have serious implications for data privacy and system security, especially if the guestbook stores sensitive information. Defenders should prioritize patching or mitigating this vulnerability to prevent potential exploitation.

## Attack Chain

1. An unauthenticated attacker identifies an MGB OpenSource Guestbook 0.7.0.2 installation.
2. The attacker crafts a malicious SQL injection payload.
3. The attacker sends a GET request to `email.php` with the crafted SQL payload within the `id` parameter.
4. The `email.php` script processes the request without proper sanitization of the `id` parameter.
5. The injected SQL code is executed against the guestbook database.
6. The attacker retrieves sensitive database information, such as table names and column names.
7. The attacker may further exploit the SQL injection to extract user data or modify database contents.
8. The attacker gains unauthorized access to sensitive information or control over the guestbook application.

## Impact

Successful exploitation of CVE-2018-25411 can lead to unauthorized access to sensitive database information. This could include user credentials, personal details, or other confidential data stored within the MGB OpenSource Guestbook database. The number of affected installations is unknown. Sectors using this guestbook software are potentially vulnerable. A successful attack could result in data breaches, identity theft, or further compromise of the web server.

## Recommendation

*   Apply available patches or upgrades to MGB OpenSource Guestbook to address CVE-2018-25411 if available from the vendor.
*   Implement input validation and sanitization on the `id` parameter in `email.php` to prevent SQL injection attacks.
*   Deploy the Sigma rule `Detect MGB OpenSource Guestbook SQL Injection via email.php` to detect exploitation attempts.
*   Monitor web server logs for suspicious GET requests to `email.php` containing SQL injection payloads.
*   Restrict access to the database server from the web server to only necessary accounts and privileges.
