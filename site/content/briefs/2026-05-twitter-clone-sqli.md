---
title: Twitter-Clone 1 SQL Injection Vulnerability (CVE-2018-25364)
slug: 2026-05-twitter-clone-sqli
description: Twitter-Clone 1 is vulnerable to SQL injection via the name parameter in the search.php endpoint, allowing unauthenticated attackers to execute arbitrary SQL queries and extract sensitive information (CVE-2018-25364).
date: "2026-05-26T14:14:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2018-25364
  - web-application
products:
  - Twitter-Clone 1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25364
    cvss: 8.2
    epss: 0.00065
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25364
  - https://github.com/Fyffe/PHP-Twitter-Clone/
  - https://www.exploit-db.com/exploits/45247
  - https://www.vulncheck.com/advisories/twitter-clone-1-sql-injection-via-search-php
rules:
  - title: Detects CVE-2018-25364 Exploitation — SQL Injection in search.php
    description: Detects CVE-2018-25364 exploitation — Suspicious requests to search.php endpoint containing SQL injection attempts in the name parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2018-25364 Exploitation — search.php HTTP POST with SQL
    description: Detects CVE-2018-25364 exploitation — Detects a POST request to the vulnerable endpoint with potential SQL injection.
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

Twitter-Clone 1 is susceptible to a SQL injection vulnerability (CVE-2018-25364) affecting the search functionality. Unauthenticated attackers can exploit this flaw by injecting malicious SQL code into the `name` parameter of the `search.php` endpoint. This allows them to execute arbitrary SQL queries against the application's database. Successful exploitation can lead to the extraction of sensitive data, including usernames, credentials, and underlying system information. The vulnerability can be exploited using error-based and union-based SQL injection techniques.

## Attack Chain

1.  The attacker identifies a vulnerable instance of Twitter-Clone 1.
2.  The attacker crafts a malicious SQL injection payload. This payload is designed to extract data from the database or perform other unauthorized actions.
3.  The attacker sends an HTTP GET or POST request to the `search.php` endpoint, embedding the malicious SQL payload within the `name` parameter.
4.  The `search.php` script processes the request and incorporates the attacker-supplied `name` parameter into a SQL query without proper sanitization or parameterization.
5.  The database server executes the attacker's malicious SQL query.
6.  The database server returns the results of the malicious query to the `search.php` script.
7.  The `search.php` script displays the results of the query (including sensitive data or error messages revealing database structure) to the attacker.
8.  The attacker uses extracted data to further compromise the system or gain unauthorized access to user accounts.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2018-25364) can lead to the unauthorized disclosure of sensitive information stored within the application's database. This may include usernames, passwords, email addresses, and other personal data of users. Attackers can leverage the vulnerability to gain complete control over the application's data and potentially the underlying server.

## Recommendation

*   Inspect web server logs for suspicious requests to `search.php` containing SQL syntax within the `name` parameter to detect exploitation attempts.
*   Deploy the Sigma rule detecting SQL injection attempts against the `search.php` endpoint.
*   Consider using a Web Application Firewall (WAF) with updated rules to block SQL injection attacks against web applications.
