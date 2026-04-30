---
title: SQL Injection Vulnerability in jkev Record Management System 1.0 (CVE-2026-5575)
slug: 2026-04-jkev-sql-injection
description: A SQL injection vulnerability (CVE-2026-5575) exists in the Login component of SourceCodester/jkev Record Management System 1.0, allowing remote attackers to execute arbitrary SQL commands by manipulating the Username parameter in index.php.
date: "2026-04-05T15:16:43Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - cve-2026-5575
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5575
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5575
  - https://github.com/whatyourname12345/CVE/blob/main/PRMS/cve_SQL.md
  - https://vuldb.com/vuln/355345
rules:
  - title: Detecting JKEV Record Management System SQL Injection Attempt
    description: Detects potential SQL injection attempts in the Username parameter of the JKEV Record Management System login page.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - sql_injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detecting JKEV Record Management System SQL Injection via POST
    description: Detects potential SQL injection attempts in the Username parameter of the JKEV Record Management System login page using POST requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - sql_injection
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5575 is a critical security flaw discovered in SourceCodester/jkev Record Management System version 1.0. Specifically, a SQL injection vulnerability is present within the Login component's index.php file. The vulnerability allows unauthenticated, remote attackers to inject malicious SQL code via the Username parameter. Given that an exploit is publicly available, the risk of exploitation is elevated. This could lead to unauthorized data access, modification, or deletion, potentially compromising the entire Record Management System. Organizations using this software should take immediate action to mitigate the risk.

## Attack Chain

1.  An attacker identifies a vulnerable instance of SourceCodester/jkev Record Management System 1.0 exposed to the internet.
2.  The attacker crafts a malicious HTTP request targeting the `index.php` file associated with the Login component.
3.  Within the HTTP request, the attacker injects SQL code into the `Username` parameter of the login form.
4.  The application fails to properly sanitize or validate the `Username` input before incorporating it into an SQL query.
5.  The injected SQL code is executed against the underlying database, potentially bypassing authentication.
6.  The attacker gains unauthorized access to sensitive data stored in the database, such as user credentials or records.
7.  The attacker may modify or delete data, depending on the privileges of the database user account used by the application.
8.  The attacker can potentially pivot to other systems or networks using the compromised database server.

## Impact

Successful exploitation of CVE-2026-5575 can lead to complete compromise of the jkev Record Management System. Attackers can steal sensitive data, modify existing records, or even delete the entire database. This could result in significant financial losses, reputational damage, and legal liabilities. The vulnerable software is used to manage records, so successful attacks could expose confidential customer or business data depending on the nature of the records being managed.

## Recommendation

*   Deploy the Sigma rule `Detecting JKEV Record Management System SQL Injection Attempt` to your SIEM to identify exploitation attempts targeting the vulnerable login page.
*   Inspect web server logs for requests to `/index.php` with suspicious characters or SQL keywords in the `Username` parameter to identify potential attack attempts (see `rules` section).
*   Implement input validation and sanitization on the `Username` parameter in `index.php` to prevent SQL injection, addressing CVE-2026-5575.
