---
title: eNdonesia Portal 8.7 SQL Injection Vulnerability (CVE-2018-25405)
slug: 2026-05-endonesia-sql-injection
description: eNdonesia Portal version 8.7 is vulnerable to SQL injection (CVE-2018-25405), allowing unauthenticated attackers to execute arbitrary SQL queries through the artid, cid, did, contid, and aboutid parameters in mod.php, potentially leading to the extraction of sensitive database information.
date: "2026-05-30T16:18:03Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve-2018-25405
vendors:
  - eNdonesia Portal
products:
  - eNdonesia Portal 8.7
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25405
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25405
rules:
  - title: Detects CVE-2018-25405 Exploitation - eNdonesia Portal SQL Injection Attempt
    description: Detects CVE-2018-25405 exploitation - SQL injection attempts in eNdonesia Portal 8.7 through vulnerable parameters in mod.php
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2018-25405 Exploitation - eNdonesia Portal SQL Injection Error Responses
    description: Detects CVE-2018-25405 exploitation - HTTP error responses indicative of SQL injection attempts in eNdonesia Portal 8.7
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

eNdonesia Portal 8.7 is susceptible to SQL injection vulnerabilities. Disclosed in 2018 and identified as CVE-2018-25405, these flaws allow unauthenticated attackers to inject malicious SQL code into vulnerable parameters. The affected parameters, artid, cid, did, contid, and aboutid, are located within the `mod.php` script. Successful exploitation could lead to unauthorized access to sensitive database information, including usernames, database names, and version details. Defenders should implement appropriate input validation and sanitization to mitigate this risk.

## Attack Chain

1.  The attacker identifies an eNdonesia Portal 8.7 instance running a vulnerable version of the software.
2.  The attacker crafts a malicious HTTP request targeting the `mod.php` script.
3.  The attacker injects SQL code into one of the vulnerable parameters: `artid`, `cid`, `did`, `contid`, or `aboutid`. For example, `mod.php?artid=1'+UNION+SELECT+version()--`.
4.  The web server processes the request and executes the injected SQL query against the database.
5.  The database server executes the malicious SQL query due to the lack of proper input validation and sanitization in the `mod.php` script.
6.  The database server returns the results of the injected SQL query to the web server. This may include sensitive information such as database version, user credentials, or other application data.
7.  The web server includes the results of the SQL query in the HTTP response to the attacker.
8.  The attacker parses the HTTP response to extract the sensitive information obtained from the database. The attacker may use this information for further malicious activities.

## Impact

Successful exploitation of this SQL injection vulnerability can allow attackers to extract sensitive information from the eNdonesia Portal database. This may include usernames, passwords, database names, version details, and other confidential data. The extracted information can be used for subsequent attacks, such as account compromise, data theft, or further exploitation of the system.

## Recommendation

*   Deploy the Sigma rule to detect SQL injection attempts targeting the vulnerable parameters in `mod.php`.
*   Apply input validation and sanitization to all user-supplied input, especially the `artid`, `cid`, `did`, `contid`, and `aboutid` parameters in `mod.php`, to prevent SQL injection attacks.
*   Ensure that the eNdonesia Portal installation is updated to a version that addresses CVE-2018-25405.
*   Monitor web server logs for suspicious activity, such as unusual HTTP requests or database errors, to identify potential SQL injection attempts.
