---
title: ResourceSpace 8.6 SQL Injection Vulnerability
slug: 2026-04-resourcespace-sqli
description: ResourceSpace 8.6 is vulnerable to SQL injection, allowing unauthenticated attackers to execute arbitrary SQL queries via the 'ref' parameter in GET requests to the watched_searches.php endpoint, leading to sensitive data extraction.
date: "2026-04-05T21:16:43Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - sqli
  - cve-2019-25662
  - resourcespace
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25662
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25662
  - https://www.exploit-db.com/exploits/46308
  - https://www.resourcespace.com/
  - https://www.resourcespace.com/get
  - https://www.vulncheck.com/advisories/resourcespace-sql-injection-via-watched-searches-php
rules:
  - title: Detect ResourceSpace SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the /watched_searches.php endpoint in ResourceSpace by monitoring for suspicious characters and SQL keywords in the 'ref' parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect ResourceSpace SQL Injection Attempt - Error Based
    description: Detects potential error-based SQL injection attempts against ResourceSpace by monitoring for specific error-inducing payloads in the 'ref' parameter of requests to /watched_searches.php.
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

ResourceSpace 8.6 is susceptible to a critical SQL injection vulnerability (CVE-2019-25662) that allows unauthenticated attackers to execute arbitrary SQL queries. The vulnerability is located within the watched_searches.php endpoint and is triggered through the 'ref' parameter in GET requests. By injecting malicious SQL code into this parameter, attackers can bypass authentication and directly interact with the database, potentially extracting sensitive information such as usernames and credentials. This vulnerability poses a significant risk as it does not require any prior authentication, making exploitation straightforward for remote attackers. ResourceSpace is an open-source digital asset management (DAM) system. Successful exploitation of this vulnerability allows attackers to potentially compromise the entire system.

## Attack Chain

1. An unauthenticated attacker identifies a ResourceSpace 8.6 instance.
2. The attacker crafts a malicious SQL injection payload designed to extract data or manipulate the database. This payload is injected into the 'ref' parameter.
3. The attacker sends a GET request to the `/watched_searches.php` endpoint with the crafted SQL payload within the `ref` parameter (e.g., `watched_searches.php?ref=SQL_injection_payload`).
4. The ResourceSpace application improperly processes the attacker-supplied SQL payload without proper sanitization.
5. The malicious SQL query is executed against the underlying database.
6. The database server processes the query and returns the results to the ResourceSpace application.
7. The ResourceSpace application displays the results, which may include sensitive information like usernames, passwords, or other confidential data.
8. The attacker retrieves the extracted sensitive data from the application's response.

## Impact

Successful exploitation of the SQL injection vulnerability in ResourceSpace 8.6 can lead to the complete compromise of the affected system. Attackers can gain unauthorized access to sensitive data, including user credentials, financial information, and proprietary data. This could lead to financial loss, reputational damage, and legal liabilities. Given the nature of digital asset management systems, the compromised data might include valuable intellectual property or personally identifiable information (PII), potentially impacting a large number of individuals.

## Recommendation

*   Apply available patches or upgrade to a secure version of ResourceSpace to remediate CVE-2019-25662.
*   Deploy the Sigma rule `Detect ResourceSpace SQL Injection Attempt` to monitor for exploitation attempts against the `/watched_searches.php` endpoint.
*   Implement input validation and sanitization on the 'ref' parameter within the `watched_searches.php` endpoint to prevent SQL injection.
*   Enable web server logging and monitor for suspicious GET requests to `watched_searches.php` containing unusual characters or SQL keywords.
