---
title: Yot CMS 3.3.1 SQL Injection Vulnerability (CVE-2018-25425)
slug: 2026-05-yot-cms-sqli
description: Yot CMS 3.3.1 is vulnerable to SQL injection, allowing unauthenticated attackers to execute arbitrary SQL queries by injecting malicious code through the aid and cid parameters in GET requests, potentially leading to database information disclosure.
date: "2026-05-30T16:21:39Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - sql-injection
  - cve
  - web-application
vendors:
  - SourceForge
products:
  - Yot CMS 3.3.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25425
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25425
  - https://ayera.dl.sourceforge.net/project/yot/Yot%203.3.1.zip
  - https://www.exploit-db.com/exploits/45768
  - https://www.vulncheck.com/advisories/yot-cms-sql-injection-via-aid-and-cid-parameters
  - https://yot.sourceforge.io/
rules:
  - title: Detect Yot CMS SQL Injection Attempt via GET Parameters
    description: Detects CVE-2018-25425 exploitation - SQL injection attempts in Yot CMS 3.3.1 via aid or cid parameters in GET requests to index.php
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
  - title: Detect SQL Keywords in URI Query
    description: Detects possible SQL Injection attempts by searching for SQL keywords in URI queries
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
rules_count: 2
---

Yot CMS 3.3.1 is susceptible to an SQL injection vulnerability (CVE-2018-25425) that enables unauthenticated attackers to execute arbitrary SQL queries. The vulnerability stems from insufficient input sanitization within the application, specifically affecting the `aid` and `cid` parameters. By crafting malicious SQL payloads within GET requests to the `index.php` endpoint, attackers can potentially extract sensitive database information, including table and column names. This vulnerability poses a significant risk, as it allows unauthorized access to the underlying database, compromising the confidentiality and integrity of the CMS and its data.

## Attack Chain

1.  An unauthenticated attacker identifies a Yot CMS 3.3.1 instance.
2.  The attacker crafts a malicious SQL payload designed to extract database information. This payload is injected into either the `aid` or `cid` parameter of a GET request.
3.  The attacker sends the crafted GET request to the `index.php` endpoint of the vulnerable Yot CMS instance. For example: `index.php?aid=malicious_sql_payload` or `index.php?cid=malicious_sql_payload`.
4.  The Yot CMS application processes the GET request without properly sanitizing the `aid` or `cid` parameter.
5.  The malicious SQL payload is passed directly to the database server.
6.  The database server executes the injected SQL query.
7.  The database server returns the results of the injected SQL query to the Yot CMS application.
8.  The Yot CMS application displays the extracted database information, potentially revealing sensitive data like table names, column names, and data contained within the tables.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2018-25425) allows unauthenticated attackers to execute arbitrary SQL queries on the Yot CMS 3.3.1 database. This can lead to the disclosure of sensitive information, such as usernames, passwords, and other confidential data stored in the database. The attacker could potentially gain complete control over the database, leading to data modification, deletion, or the insertion of malicious content into the CMS.

## Recommendation

*   Apply appropriate input validation and sanitization techniques to all user-supplied input, especially within the `aid` and `cid` parameters of `index.php`, to prevent SQL injection attacks as described in CVE-2018-25425.
*   Deploy the Sigma rule "Detect Yot CMS SQL Injection Attempt via GET Parameters" to detect exploitation attempts in web server logs.
*   Monitor web server logs for suspicious GET requests to `index.php` containing SQL keywords or special characters in the `aid` or `cid` parameters.
