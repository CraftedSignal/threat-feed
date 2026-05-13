---
title: JoomSport WordPress Plugin Vulnerable to Time-Based Blind SQL Injection (CVE-2026-6929)
slug: 2026-05-joomsport-sqli
description: The JoomSport plugin for WordPress is vulnerable to time-based blind SQL Injection (CVE-2026-6929) via the 'sortf' parameter in versions up to 5.7.7, allowing unauthenticated attackers to extract sensitive information from the database.
date: "2026-05-13T15:51:02Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - sqli
  - wordpress
  - cve-2026-6929
  - joomsport
  - injection
vendors:
  - WordPress
products:
  - 'JoomSport – for Sports: Team & League, Football, Hockey & more plugin <= 5.7.7'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6929
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6929
rules:
  - title: Detect CVE-2026-6929 Exploitation Attempt via JoomSport SQL Injection
    description: Detects CVE-2026-6929 exploitation attempt via crafted requests to JoomSport plugin containing SQL injection attempts in the sortf parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-6929 Exploitation Attempt via JoomSport Encoded SQL Injection
    description: Detects CVE-2026-6929 exploitation attempt via crafted requests to JoomSport plugin containing URL encoded SQL injection attempts in the sortf parameter.
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

The JoomSport – for Sports: Team & League, Football, Hockey & more plugin for WordPress is susceptible to a time-based blind SQL Injection vulnerability. This flaw, identified as CVE-2026-6929, affects all versions up to and including 5.7.7. The vulnerability exists due to insufficient input sanitization of the 'sortf' parameter and inadequate preparation of the SQL query. This allows unauthenticated attackers to inject malicious SQL code into existing queries, potentially leading to the extraction of sensitive database information. Successful exploitation could compromise the integrity and confidentiality of the WordPress site's data.

## Attack Chain

1. An unauthenticated attacker sends a malicious HTTP request to the WordPress site.
2. The request targets an endpoint that utilizes the JoomSport plugin.
3. The attacker crafts the request to include a 'sortf' parameter containing a time-based blind SQL injection payload.
4. The JoomSport plugin processes the request without properly sanitizing the 'sortf' parameter.
5. The unsanitized input is incorporated into an SQL query executed against the WordPress database.
6. The injected SQL code leverages time-based delays to infer information about the database structure and content.
7. The attacker analyzes the response times to determine the results of the injected SQL queries.
8. Through repeated requests, the attacker extracts sensitive information, such as usernames, passwords, or other confidential data stored in the database.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to extract sensitive data from the WordPress database. This could include usernames, passwords, email addresses, and other confidential information. The impact ranges from data breaches and compromised user accounts to potential defacement of the website and further malicious activities. If the database contains sensitive financial data, the consequences could be even more severe.

## Recommendation

*   Upgrade the JoomSport – for Sports: Team & League, Football, Hockey & more plugin to the latest version to patch CVE-2026-6929.
*   Deploy the Sigma rule "Detect CVE-2026-6929 Exploitation Attempt via JoomSport SQL Injection" to your SIEM to identify potential exploitation attempts.
*   Monitor web server logs for suspicious requests containing SQL injection payloads in the 'sortf' parameter to identify and block malicious activity.
