---
title: eNdonesia Portal v8.7 SQL Injection Vulnerability
slug: 2026-03-endonesia-sql-injection
description: eNdonesia Portal v8.7 is vulnerable to SQL injection allowing unauthenticated attackers to execute arbitrary SQL queries via the bid parameter in banners.php, potentially leading to sensitive data extraction.
date: "2026-03-24T12:16:06Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - sql-injection
  - web-application
  - cve-2019-25643
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25643
  - https://www.exploit-db.com/exploits/46559
  - https://www.vulncheck.com/advisories/endonesia-portal-sql-injection-via-banners-php
rules:
  - title: Detecting eNdonesia banners.php SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the banners.php endpoint in eNdonesia Portal v8.7
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detecting eNdonesia banners.php SQL Injection via POST
    description: Detects potential SQL injection attempts targeting the banners.php endpoint in eNdonesia Portal v8.7 via POST requests
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

eNdonesia Portal v8.7 is susceptible to SQL injection vulnerabilities. Unauthenticated attackers can exploit this flaw by injecting malicious SQL code through the `bid` parameter in the `banners.php` script. The vulnerability allows attackers to execute arbitrary SQL queries against the application's database. Successful exploitation could lead to the unauthorized extraction of sensitive information, including database schema details from `INFORMATION_SCHEMA` tables. This vulnerability, identified as CVE-2019-25643, poses a significant risk due to the ease of exploitation and the potential for extensive data compromise. The vulnerability was reported on March 24, 2026.

## Attack Chain

1.  An unauthenticated attacker identifies an eNdonesia Portal v8.7 instance.
2.  The attacker crafts a malicious SQL payload designed to extract data from the `INFORMATION_SCHEMA` tables.
3.  The attacker constructs a GET request targeting `banners.php`.
4.  The crafted SQL payload is injected into the `bid` parameter of the GET request: `banners.php?bid=<SQL_payload>`.
5.  The web server processes the request and executes the injected SQL query against the database.
6.  The database returns the results of the SQL query, potentially including sensitive data or schema information.
7.  The attacker receives the database response containing the extracted information.
8.  The attacker analyzes the extracted information to further compromise the system or exfiltrate sensitive data.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to the unauthorized disclosure of sensitive data, including user credentials, financial information, and other confidential data stored in the eNdonesia Portal v8.7 database. The impact could range from defacement of the website to complete compromise of the underlying database server. Although the number of affected installations is unknown, any instance of eNdonesia Portal v8.7 is potentially vulnerable.

## Recommendation

*   Deploy the Sigma rule `Detecting eNdonesia banners.php SQL Injection Attempt` to your SIEM to identify exploitation attempts targeting the `banners.php` endpoint.
*   Examine web server logs for GET requests to `banners.php` containing suspicious SQL syntax within the `bid` parameter (reference the log source in the Sigma rule).
*   Apply available patches or updates for eNdonesia Portal v8.7 to remediate the CVE-2019-25643 vulnerability.
