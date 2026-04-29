---
title: MyT-PM 1.5.1 SQL Injection Vulnerability
slug: 2026-04-mytpm-sqli
description: MyT-PM 1.5.1 is vulnerable to SQL injection, allowing authenticated attackers to execute arbitrary SQL queries via the Charge[group_total] parameter.
date: "2026-04-12T13:16:34Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve-2019-25713
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25713
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25713
  - https://manageyourteam.net/
  - https://sourceforge.net/projects/myt/
  - https://www.exploit-db.com/exploits/46084
  - https://www.vulncheck.com/advisories/myt-pm-sql-injection-via-charge-group-total-parameter
iocs:
  - type: url
    value: https://manageyourteam.net/
  - type: url
    value: https://sourceforge.net/projects/myt/
  - type: url
    value: https://www.exploit-db.com/exploits/46084
  - type: url
    value: https://www.vulncheck.com/advisories/myt-pm-sql-injection-via-charge-group-total-parameter
ioc_counts:
  url: 4
rules:
  - title: Detect SQL Injection Attempts in MyT-PM Charge Endpoint
    description: Detects potential SQL injection attempts targeting the /charge/admin endpoint in MyT-PM through the Charge[group_total] parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1212
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection UNION SELECT
    description: Detects UNION SELECT strings in web requests, indicating possible SQL injection attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1212
    data_sources:
      - webserver
      - linux
rules_count: 2
---

MyT-PM 1.5.1 is susceptible to an SQL injection vulnerability (CVE-2019-25713) that enables authenticated attackers to execute arbitrary SQL queries. This vulnerability exists due to insufficient input sanitization of the `Charge[group_total]` parameter. By sending specially crafted POST requests to the `/charge/admin` endpoint, an attacker can inject malicious SQL code, potentially leading to sensitive data extraction, data manipulation, or other unauthorized actions. This vulnerability poses a significant risk to organizations using MyT-PM 1.5.1 as it could compromise the integrity and confidentiality of their data.

## Attack Chain

1. An attacker authenticates to the MyT-PM 1.5.1 application.
2. The attacker crafts a malicious POST request targeting the `/charge/admin` endpoint.
3. Within the POST request, the attacker injects SQL code into the `Charge[group_total]` parameter.
4. The application processes the request without properly sanitizing the `Charge[group_total]` parameter.
5. The injected SQL code is executed against the underlying database.
6. The attacker leverages the SQL injection to extract sensitive data (e.g., user credentials, financial information) using error-based, time-based blind, or stacked query payloads.
7. The attacker may further manipulate data within the database, potentially altering records or creating new entries.
8. The attacker achieves complete control over the database, potentially leading to full system compromise.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to the unauthorized disclosure of sensitive information, such as user credentials, financial records, and other confidential data stored within the MyT-PM database. Attackers may also be able to modify or delete data, leading to data integrity issues and potential disruption of business operations. This could result in financial losses, reputational damage, and legal repercussions for affected organizations.

## Recommendation

*   Apply patches or upgrade to a secure version of MyT-PM that addresses CVE-2019-25713.
*   Deploy the provided Sigma rule to detect potentially malicious requests containing SQL injection attempts targeting the `/charge/admin` endpoint and the `Charge[group_total]` parameter.
*   Implement input validation and sanitization measures to prevent SQL injection vulnerabilities in MyT-PM and other web applications.
*   Monitor web server logs for suspicious POST requests to `/charge/admin` with unusual characters or SQL keywords in the `Charge[group_total]` parameter.
