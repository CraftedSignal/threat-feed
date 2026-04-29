---
title: XATABoost CMS 1.0.0 SQL Injection Vulnerability
slug: 2026-04-xataboost-sql-injection
description: XATABoost CMS 1.0.0 is vulnerable to union-based SQL injection, allowing unauthenticated attackers to manipulate database queries by injecting SQL code through the id parameter via GET requests to news.php, enabling extraction of sensitive database information.
date: "2026-04-29T20:16:25Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve
vendors:
  - xataboost
products:
  - xataboost cms 1.0.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25300
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25300
  - http://www2.xataboost.com
  - https://www.exploit-db.com/exploits/44622
  - https://www.vulncheck.com/advisories/xataboost-cms-sql-injection-via-news-php
rules:
  - title: Detect XATABoost CMS SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting XATABoost CMS news.php via GET requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect XATABoost CMS SQL Injection via Comments
    description: Detects potential SQL injection attempts targeting XATABoost CMS news.php via GET requests using comments.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

XATABoost CMS 1.0.0 is susceptible to a union-based SQL injection vulnerability (CVE-2018-25300). This flaw enables unauthenticated attackers to inject malicious SQL code through the `id` parameter in `news.php` via GET requests. By crafting specific payloads, attackers can manipulate database queries to extract sensitive information. This vulnerability poses a significant risk, as it could lead to data breaches, account compromise, and further exploitation of the affected system. The targeted exploitation vector is the `news.php` file, making it a critical area for monitoring and mitigation.

## Attack Chain

1.  An unauthenticated attacker identifies the `news.php` endpoint.
2.  The attacker crafts a malicious GET request targeting the `id` parameter within `news.php`. This payload contains SQL injection code.
3.  The server-side application fails to properly sanitize the `id` parameter before constructing the SQL query.
4.  The injected SQL code is executed against the database.
5.  The attacker uses UNION clauses to extract sensitive information from other database tables.
6.  The extracted data is returned as part of the HTTP response.
7.  The attacker parses the HTTP response to retrieve the exfiltrated data.
8.  The attacker uses the exfiltrated data for further malicious activities (e.g., privilege escalation, lateral movement).

## Impact

Successful exploitation of this SQL injection vulnerability can result in the unauthorized disclosure of sensitive information stored in the XATABoost CMS database. This includes user credentials, financial data, or other confidential information. The impact could range from a single compromised system to a full-scale data breach, depending on the scope and sensitivity of the data stored within the database. Without further context on affected deployments, the number of potential victims is hard to quantify, but any public-facing XATABoost CMS 1.0.0 instance is vulnerable.

## Recommendation

*   Deploy the Sigma rule `Detect XATABoost CMS SQL Injection Attempt` to identify malicious GET requests targeting the `news.php` endpoint and tune for your environment.
*   Implement input validation and sanitization on the `id` parameter in the `news.php` file to prevent SQL injection attacks.
*   Upgrade to a patched version of XATABoost CMS or implement a web application firewall (WAF) rule to mitigate the vulnerability.
*   Monitor web server logs for suspicious activity related to `news.php` and unusual SQL queries.
*   Review and restrict database user permissions to minimize the impact of successful SQL injection attacks.
