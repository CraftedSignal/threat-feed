---
title: ASP.NET jVideo Kit 1.0 SQL Injection Vulnerability
slug: 2026-03-jvideo-sql-injection
description: ASP.NET jVideo Kit 1.0 is vulnerable to SQL injection via the 'query' parameter in the search functionality, allowing unauthenticated attackers to inject malicious SQL payloads to extract sensitive database information.
date: "2026-03-26T12:16:05Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - sql-injection
  - vulnerability
  - asp.net
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25205
  - https://www.exploit-db.com/exploits/44739
  - https://www.mediasoftpro.com/video-sharing-script/mvc/
  - https://www.vulncheck.com/advisories/asp-net-jvideo-kit-sql-injection-via-query-parameter
rules:
  - title: Detect SQL Injection Attempts in jVideo Kit Search
    description: Detects potential SQL injection attempts targeting the /search endpoint in ASP.NET jVideo Kit 1.0 by looking for common SQL injection keywords in the query parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
  - title: Detect SQL Injection Error Responses
    description: Detects potential SQL injection attempts by monitoring web server logs for specific error status codes and messages associated with SQL errors after a request to /search
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - windows
rules_count: 2
---

ASP.NET jVideo Kit 1.0 is susceptible to an SQL injection vulnerability (CVE-2018-25205) affecting its search functionality. This vulnerability enables unauthenticated attackers to inject arbitrary SQL commands by manipulating the 'query' parameter. The attack can be carried out via both GET and POST requests directed towards the `/search` endpoint. Successful exploitation allows attackers to perform boolean-based blind or error-based SQL injection techniques, potentially leading to the extraction of sensitive database information. This vulnerability was published on March 26, 2026. Defenders should prioritize patching or mitigating this vulnerability to prevent unauthorized access to sensitive data.

## Attack Chain

1. An unauthenticated attacker identifies an ASP.NET jVideo Kit 1.0 instance.
2. The attacker crafts a malicious SQL payload designed to exploit the 'query' parameter in the `/search` endpoint.
3. The attacker sends a GET or POST request to the `/search` endpoint with the crafted SQL payload embedded in the `query` parameter.
4. The ASP.NET application fails to properly sanitize the input from the `query` parameter before using it in a database query.
5. The malicious SQL payload is executed against the database.
6. Depending on the SQL injection technique (boolean-based blind, error-based), the attacker infers information about the database structure and data.
7. The attacker refines the SQL payloads to extract sensitive data, such as usernames, passwords, or other confidential information.
8. The attacker exfiltrates the extracted data for malicious purposes.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2018-25205) allows unauthenticated attackers to extract sensitive information from the affected ASP.NET jVideo Kit 1.0 database. The number of affected installations is unknown, but the vulnerability could lead to data breaches, compromise of user accounts, and potential reputational damage to organizations using the vulnerable software. The affected software is a video sharing script, making content websites a key target.

## Recommendation

*   Apply available patches or updates for ASP.NET jVideo Kit 1.0 to address CVE-2018-25205.
*   Implement input validation and sanitization measures to prevent SQL injection attacks against the `/search` endpoint, focusing on the 'query' parameter.
*   Deploy the following Sigma rule to detect exploitation attempts targeting the `/search` endpoint with potentially malicious SQL queries.
