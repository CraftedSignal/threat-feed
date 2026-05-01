---
title: itsourcecode Electronic Judging System SQL Injection Vulnerability (CVE-2026-7555)
slug: 2024-01-electronic-judging-sql-injection
description: A remote SQL injection vulnerability (CVE-2026-7555) exists in itsourcecode Electronic Judging System 1.0 via manipulation of the Username argument in the /intrams/login.php file, potentially leading to unauthorized data access and modification.
date: "2024-01-03T18:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - vulnerability
  - web-application
vendors:
  - itsourcecode
products:
  - Electronic Judging System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7555
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7555
rules:
  - title: Detect Suspicious Login Attempts via SQL Injection
    description: Detects suspicious login attempts to /intrams/login.php with potential SQL injection payloads in the Username parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Payloads in URI Queries
    description: Detects common SQL injection keywords in URI queries, indicating a potential attack attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

itsourcecode Electronic Judging System 1.0 is vulnerable to SQL injection in the /intrams/login.php file. The vulnerability, identified as CVE-2026-7555, allows a remote attacker to inject malicious SQL code by manipulating the `Username` argument. The vulnerability was reported on 2026-05-01. Successful exploitation could lead to unauthorized access to sensitive data, modification of existing data, or even complete compromise of the database. The availability of a public exploit increases the risk of widespread exploitation. This poses a significant threat to organizations using the affected judging system, potentially disrupting operations and compromising confidential information.

## Attack Chain

1.  The attacker identifies an instance of itsourcecode Electronic Judging System 1.0 running on a target server.
2.  The attacker crafts a malicious HTTP POST request targeting the `/intrams/login.php` endpoint.
3.  Within the POST request, the attacker manipulates the `Username` parameter with a SQL injection payload.
4.  The server-side application improperly processes the attacker-supplied `Username` value, failing to sanitize special characters.
5.  The unsanitized `Username` value is incorporated into a SQL query executed against the application database.
6.  The injected SQL code modifies the query's intended logic, potentially bypassing authentication or extracting sensitive data.
7.  The database server executes the modified SQL query, returning the results to the web application.
8.  The attacker gains unauthorized access to sensitive information, such as user credentials, judging data, or other confidential application data.

## Impact

Successful exploitation of this SQL injection vulnerability could allow attackers to bypass authentication, gain access to sensitive judging data, modify existing records, or potentially gain complete control of the database server. This could lead to data breaches, financial loss, reputational damage, and disruption of judging events. The lack of specific victim count or sector information in the source data makes quantifying the exact impact challenging.

## Recommendation

*   Apply appropriate input validation and sanitization techniques to the `Username` parameter in `/intrams/login.php` to mitigate the SQL injection vulnerability.
*   Deploy the Sigma rule `Detect Suspicious Login Attempts via SQL Injection` to detect exploitation attempts targeting `/intrams/login.php`.
*   Monitor web server logs for suspicious POST requests containing unusual characters or SQL keywords in the `Username` parameter.
*   Consider implementing a web application firewall (WAF) with rules to block common SQL injection patterns.
