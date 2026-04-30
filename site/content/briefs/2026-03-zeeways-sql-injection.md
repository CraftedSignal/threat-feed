---
title: Zeeways Matrimony CMS Unauthenticated SQL Injection Vulnerability
slug: 2026-03-zeeways-sql-injection
description: Zeeways Matrimony CMS is vulnerable to SQL injection via the profile_list endpoint, where an unauthenticated attacker can inject SQL code via the up_cast, s_mother, and s_religion parameters, potentially allowing them to extract sensitive information.
date: "2026-03-24T12:16:04Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - web-application
  - matrimony-cms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25635
  - http://www.zeeways.com/matrimony-cms/4/productdetail
  - https://www.exploit-db.com/exploits/46603
  - https://www.vulncheck.com/advisories/zeeways-matrimony-cms-lastest-sql-injection-via-profile-list
iocs:
  - type: url
    value: http://www.zeeways.com/matrimony-cms/4/productdetail
  - type: url
    value: https://www.exploit-db.com/exploits/46603
  - type: url
    value: https://www.vulncheck.com/advisories/zeeways-matrimony-cms-lastest-sql-injection-via-profile-list
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
  url: 3
rules:
  - title: Detect SQL Injection Attempts in Zeeways Matrimony CMS via profile_list
    description: Detects potential SQL injection attempts targeting the profile_list endpoint in Zeeways Matrimony CMS through suspicious parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection - Error Based
    description: Detects potential SQL injection attempts based on common error messages in web server logs.
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

Zeeways Matrimony CMS is susceptible to SQL injection vulnerabilities affecting the profile_list endpoint. This vulnerability allows unauthenticated attackers to inject malicious SQL code through the `up_cast`, `s_mother`, and `s_religion` parameters. Successful exploitation could lead to unauthorized access to sensitive data within the database. The vulnerability was reported in CVE-2019-25635. The vulnerable software is Zeeways Matrimony CMS, and it's crucial for organizations using this CMS to apply necessary patches or mitigations to prevent potential data breaches. Defenders should prioritize monitoring web server logs for suspicious activity targeting these specific parameters and the `profile_list` endpoint.

## Attack Chain

1. An unauthenticated attacker identifies a Zeeways Matrimony CMS instance.
2. The attacker crafts a malicious HTTP GET or POST request targeting the `profile_list` endpoint.
3. The attacker injects SQL code into the `up_cast`, `s_mother`, or `s_religion` parameters of the HTTP request.
4. The web server processes the request and executes the injected SQL code against the database.
5. Depending on the injected SQL, the attacker can extract sensitive information from the database, such as user credentials or personal details, using time-based or error-based techniques.
6. The attacker analyzes the extracted data to identify valuable information.
7. The attacker may use the extracted credentials to further compromise the system or access other resources.

## Impact

Successful exploitation of this SQL injection vulnerability could lead to a full database compromise, potentially exposing sensitive user data including personal information, credentials, and financial details. This can result in significant reputational damage, financial losses due to regulatory fines, and legal repercussions for organizations using the vulnerable Zeeways Matrimony CMS. The impact is high due to the ease of exploitation (unauthenticated) and the potential for complete data exfiltration.

## Recommendation

*   Inspect web server logs for suspicious HTTP requests targeting the `/profile_list` endpoint with SQL injection attempts in the `up_cast`, `s_mother`, and `s_religion` parameters (see IOC table and enable webserver logging).
*   Apply available patches or updates for Zeeways Matrimony CMS to address CVE-2019-25635.
*   Deploy the Sigma rule provided to detect exploitation attempts targeting the specified parameters in the URL.
*   Implement input validation and sanitization for all user-supplied data, especially for parameters used in database queries to prevent future SQL injection vulnerabilities.
