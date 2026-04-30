---
title: Kados R10 GreenBee SQL Injection Vulnerability (CVE-2019-25704)
slug: 2026-04-kados-sql-injection
description: Kados R10 GreenBee is vulnerable to SQL injection (CVE-2019-25704), allowing attackers to manipulate database queries via the filter_user_mail parameter, potentially leading to data extraction or modification.
date: "2026-04-05T21:16:48Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - cve-2019-25704
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25704
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25704
  - https://www.exploit-db.com/exploits/46505
rules:
  - title: Detect SQL Injection Attempts via filter_user_mail Parameter
    description: Detects potential SQL injection attempts targeting the filter_user_mail parameter in web server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Error Messages
    description: Detects common SQL error messages in web server logs, which may indicate a successful or attempted SQL injection attack.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Kados R10 GreenBee is susceptible to SQL injection attacks due to improper input validation. Specifically, the `filter_user_mail` parameter does not adequately sanitize user-supplied input, which enables attackers to inject arbitrary SQL code into database queries. Publicly disclosed as CVE-2019-25704, successful exploitation of this vulnerability can result in the unauthorized disclosure of sensitive information, modification of existing data, or potentially complete compromise of the database. The affected software is Kados R10 GreenBee; specific versions are not mentioned in the source.

## Attack Chain

1. The attacker identifies the Kados R10 GreenBee application running.
2. The attacker locates the `filter_user_mail` parameter in the application's web interface or API.
3. The attacker crafts a malicious HTTP request containing SQL code injected into the `filter_user_mail` parameter.
4. The application's backend processes the crafted request without proper sanitization.
5. The injected SQL code is executed against the database.
6. The attacker extracts sensitive data from the database, such as user credentials or financial records, by using SQL injection techniques like `UNION SELECT`.
7. Alternatively, the attacker modifies data within the database, such as altering user privileges or inserting malicious content.
8. The attacker uses the compromised database to further compromise the application or the underlying system.

## Impact

Successful exploitation of CVE-2019-25704 allows attackers to extract sensitive data (user credentials, financial records), modify existing data (alter user privileges), or potentially compromise the entire database. The number of affected installations is unknown, but unpatched systems are vulnerable. This could lead to significant data breaches, financial losses, and reputational damage.

## Recommendation

*   Inspect web server logs for HTTP requests targeting the `filter_user_mail` parameter with suspicious SQL syntax (e.g., `UNION`, `SELECT`, `--`, `/* */`) to identify potential exploitation attempts. This activity can be detected with the provided Sigma rule for webserver logs.
*   Deploy a web application firewall (WAF) rule to block requests containing SQL injection payloads targeting the `filter_user_mail` parameter.
*   Apply the patch or upgrade to a version of Kados R10 GreenBee that addresses CVE-2019-25704.
*   Implement input validation and sanitization on all user-supplied input, especially the `filter_user_mail` parameter, to prevent SQL injection attacks.
