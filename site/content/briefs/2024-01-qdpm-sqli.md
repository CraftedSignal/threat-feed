---
title: qdPM 9.1 SQL Injection Vulnerability (CVE-2018-25208)
slug: 2024-01-qdpm-sqli
description: qdPM version 9.1 is vulnerable to SQL injection, allowing unauthenticated attackers to extract sensitive database information by injecting malicious SQL code into the filter_by parameters of the timeReport endpoint.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sqli
  - cve-2018-25208
  - qdpm
vendors:
  - qdPM
products:
  - qdPM
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25208
  - https://www.exploit-db.com/exploits/45767
  - https://www.vulncheck.com/advisories/qdpm-sql-injection-via-filter-by-parameters
rules:
  - title: Detect qdPM SQL Injection Attempt via timeReport Endpoint
    description: Detects potential SQL injection attempts targeting the qdPM timeReport endpoint through the filter_by parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect qdPM SQL Injection Attempt - Generic SQLi Keywords
    description: Detects common SQL injection keywords in web requests potentially targeting qdPM.
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

qdPM 9.1 is susceptible to an SQL injection vulnerability (CVE-2018-25208) that enables unauthenticated attackers to extract database information. This vulnerability is located in the timeReport endpoint and is triggered by manipulating the filter_by parameters. By sending specially crafted POST requests containing malicious SQL code within the `filter_by[CommentCreatedFrom]` and `filter_by[CommentCreatedTo]` parameters, attackers can bypass authentication and execute arbitrary SQL queries. Successful exploitation leads to the unauthorized extraction of sensitive data stored within the qdPM database. This vulnerability poses a significant risk to organizations using qdPM 9.1, potentially exposing confidential project management data.

## Attack Chain

1.  The attacker identifies a qdPM 9.1 instance exposed to the internet.
2.  The attacker crafts a malicious POST request targeting the `/timeReport` endpoint.
3.  The attacker injects SQL code into the `filter_by[CommentCreatedFrom]` and `filter_by[CommentCreatedTo]` parameters within the POST request. The injected SQL code is designed to extract sensitive data.
4.  The attacker sends the malicious POST request to the vulnerable qdPM instance.
5.  The qdPM application fails to properly sanitize the input provided in the `filter_by` parameters.
6.  The injected SQL code is executed against the qdPM database.
7.  The database returns the results of the injected SQL query to the application.
8.  The attacker receives the extracted data in the HTTP response, potentially including usernames, passwords, project details, and other sensitive information.

## Impact

Successful exploitation of this SQL injection vulnerability allows unauthenticated attackers to extract sensitive information from the qdPM database. This can include usernames, passwords, project details, customer data, and financial information. The impact can range from data breaches and financial losses to reputational damage and legal liabilities. Due to the unauthenticated nature of the vulnerability, all qdPM 9.1 installations exposed to the internet are at risk.

## Recommendation

*   Apply the necessary patches or upgrade to a secure version of qdPM to remediate CVE-2018-25208.
*   Implement input validation and sanitization on all user-supplied data, especially within the `filter_by` parameters of the `timeReport` endpoint, to prevent SQL injection attacks.
*   Deploy the provided Sigma rule to detect malicious POST requests with SQL injection attempts targeting the `timeReport` endpoint in your web server logs.
*   Monitor web server logs for suspicious activity, such as unusual POST requests to `/timeReport` with potentially malicious SQL code in the `filter_by` parameters.
