---
title: CVE-2018-25372 - MedDream PACS Server Premium Unauthenticated SQL Injection
slug: 2026-05-meddream-sql-injection
description: MedDream PACS Server Premium 6.7.1.1 is vulnerable to SQL injection, allowing unauthenticated attackers to execute arbitrary SQL queries by injecting malicious code into the email parameter via a crafted POST request to the userSignup.php endpoint.
date: "2026-05-26T14:15:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2018-25372
  - web-application
  - meddream
vendors:
  - MedDream
products:
  - PACS Server Premium (6.7.1.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25372
    cvss: 8.2
    epss: 0.00062
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25372
  - https://www.exploit-db.com/exploits/45344
  - https://www.vulncheck.com/advisories/meddream-pacs-server-premium-sql-injection-via-email
rules:
  - title: Detect CVE-2018-25372 Exploitation — MedDream PACS Server SQL Injection Attempt
    description: Detects CVE-2018-25372 exploitation — Suspicious POST requests to userSignup.php with SQL injection attempts in the email parameter
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2018-25372 Exploitation - SQL Injection in userSignup.php via POST
    description: Detects CVE-2018-25372 - Identifies SQL injection attempts targeting the email parameter in the userSignup.php endpoint using common SQL injection techniques.
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

MedDream PACS Server Premium version 6.7.1.1 is susceptible to an SQL injection vulnerability (CVE-2018-25372). This flaw enables unauthenticated attackers to inject malicious SQL code into the email parameter of the userSignup.php endpoint. By sending specially crafted POST requests, attackers can bypass authentication and execute arbitrary SQL queries against the backend MySQL database. This can lead to the extraction of sensitive information, potentially compromising patient data and system integrity. The vulnerability was reported on May 25, 2026.

## Attack Chain

1.  The attacker identifies the `userSignup.php` endpoint as a potential target for SQL injection.
2.  The attacker crafts a malicious POST request containing SQL injection payloads within the `email` parameter.
3.  The attacker sends the crafted POST request to the `userSignup.php` endpoint.
4.  The MedDream PACS Server processes the request without proper sanitization of the `email` parameter.
5.  The injected SQL code is executed against the backend MySQL database.
6.  The attacker retrieves sensitive data from the database, such as usernames, passwords, patient records, or other confidential information.

## Impact

Successful exploitation of this vulnerability can result in the unauthorized disclosure of sensitive patient data, potentially leading to violations of privacy regulations and reputational damage. Attackers may also be able to modify or delete data, disrupt system operations, or gain further access to the server. The number of affected installations is unknown.

## Recommendation

*   Apply the latest patches or upgrades provided by MedDream to address CVE-2018-25372.
*   Implement input validation and sanitization measures to prevent SQL injection attacks.
*   Deploy the Sigma rule to detect exploitation attempts targeting the `userSignup.php` endpoint.
*   Monitor web server logs for suspicious POST requests to `userSignup.php` containing SQL syntax in the `email` parameter.
