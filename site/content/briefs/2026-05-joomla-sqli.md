---
title: Joomla com_hdwplayer 4.2 SQL Injection Vulnerability
slug: 2026-05-joomla-sqli
description: Joomla com_hdwplayer 4.2 contains an SQL injection vulnerability in the search.php file that allows unauthenticated attackers to execute arbitrary SQL queries by injecting malicious code through the hdwplayersearch parameter.
date: "2026-05-13T16:18:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - joomla
  - cve-2020-37218
  - web-application
vendors:
  - Joomla
products:
  - com_hdwplayer 4.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2020-37218
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-37218
  - https://www.exploit-db.com/exploits/48242
  - https://www.hdwplayer.com/
  - https://www.hdwplayer.com/download/
  - https://www.vulncheck.com/advisories/joomla-com-hdwplayer-sql-injection-via-search-php
rules:
  - title: Detect Joomla com_hdwplayer SQL Injection Attempt
    description: Detects CVE-2020-37218 exploitation attempt — SQL injection attempts in the hdwplayersearch parameter in Joomla com_hdwplayer.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Joomla com_hdwplayer SQL Injection Successful
    description: Detects CVE-2020-37218 exploitation — Monitors for database errors related to SQL injection attempts in Joomla com_hdwplayer.
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

Joomla com_hdwplayer 4.2 is vulnerable to SQL injection in the search.php file. Unauthenticated attackers can exploit this vulnerability by injecting malicious SQL code into the `hdwplayersearch` parameter of a POST request. This allows them to execute arbitrary SQL queries against the Joomla database. Successful exploitation can lead to the extraction of sensitive information from the `hdwplayer_videos` table, potentially compromising user data and application integrity. The vulnerability was reported in CVE-2020-37218.

## Attack Chain

1.  The attacker identifies a Joomla site using com_hdwplayer version 4.2.
2.  The attacker crafts a malicious SQL payload, designed to extract data from the `hdwplayer_videos` table.
3.  The attacker sends an HTTP POST request to `search.php`.
4.  The POST request includes the crafted SQL payload within the `hdwplayersearch` parameter.
5.  The application fails to properly sanitize the `hdwplayersearch` parameter.
6.  The application executes the attacker-controlled SQL query against the database.
7.  The database returns sensitive information from the `hdwplayer_videos` table.
8.  The attacker receives the extracted data, such as usernames, passwords, or video metadata.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2020-37218) allows unauthenticated attackers to execute arbitrary SQL queries, potentially leading to the theft of sensitive information, such as usernames, passwords, and video metadata, from the Joomla database. The vulnerability exists in Joomla com_hdwplayer 4.2. While the precise number of affected installations is unknown, any Joomla site using this extension is potentially at risk. This could lead to data breaches, reputational damage, and legal liabilities for the affected organizations.

## Recommendation

*   Inspect web server logs for POST requests to `search.php` with suspicious SQL syntax in the `hdwplayersearch` parameter to detect exploitation attempts (see Sigma rule `Detect Joomla com_hdwplayer SQL Injection Attempt`).
*   Apply available patches or updates for com_hdwplayer to remediate the SQL injection vulnerability described in CVE-2020-37218.
*   Implement input validation and sanitization on the `hdwplayersearch` parameter to prevent SQL injection attacks.
*   Deploy the Sigma rule `Detect Joomla com_hdwplayer SQL Injection Successful` to identify successful exploitation by monitoring for database errors.
