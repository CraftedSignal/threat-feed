---
title: itsourcecode Online Enrollment System SQL Injection Vulnerability (CVE-2026-5534)
slug: 2026-04-online-enrollment-sql-injection
description: CVE-2026-5534 is a SQL injection vulnerability in the itsourcecode Online Enrollment System 1.0 that allows remote attackers to execute arbitrary SQL commands by manipulating the USERID parameter in the /sms/user/index.php file, potentially leading to data exfiltration or unauthorized access.
date: "2026-04-05T03:16:00Z"
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve-2026-5534
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5534
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5534
  - https://github.com/ldan42008-ux/cve/issues/2
  - https://vuldb.com/vuln/355287
iocs:
  - type: url
    value: https://github.com/ldan42008-ux/cve/issues/2
  - type: url
    value: https://itsourcecode.com/
  - type: url
    value: https://vuldb.com/submit/782185
  - type: url
    value: https://vuldb.com/vuln/355287
  - type: url
    value: https://vuldb.com/vuln/355287/cti
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
  url: 5
rules:
  - title: Detect SQL Injection in Online Enrollment System
    description: Detects potential SQL injection attempts targeting the itsourcecode Online Enrollment System via suspicious parameters in HTTP GET requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Vulnerable Enrollment Endpoint
    description: Detects access to the vulnerable /sms/user/index.php endpoint in itsourcecode Online Enrollment System.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The itsourcecode Online Enrollment System version 1.0 is vulnerable to SQL injection via the USERID parameter in the `/sms/user/index.php` file. This vulnerability, identified as CVE-2026-5534, allows an unauthenticated, remote attacker to inject arbitrary SQL commands into the application's database queries. The vulnerability stems from insufficient sanitization of user-supplied input, leading to potential data breaches and unauthorized modification of enrollment data. This vulnerability has a readily available exploit, increasing the risk of exploitation. Defenders need to implement immediate detection and prevention measures to secure systems running the vulnerable software.

## Attack Chain

1.  An attacker identifies an instance of itsourcecode Online Enrollment System 1.0.
2.  The attacker crafts a malicious HTTP GET request targeting the `/sms/user/index.php` endpoint with the `view=edit` parameter.
3.  The attacker injects SQL code into the `id` parameter, specifically designed to exploit the `USERID` argument.
4.  The webserver passes the unsanitized `id` parameter to the underlying database query.
5.  The injected SQL code is executed within the context of the database user.
6.  The attacker might extract sensitive information from the database, such as user credentials, personally identifiable information (PII), or financial data.
7.  The attacker could modify or delete data within the database, leading to data integrity issues and denial of service.
8.  Finally, the attacker could potentially gain administrative access to the application by manipulating user privileges within the database.

## Impact

Successful exploitation of CVE-2026-5534 can lead to the compromise of sensitive student and administrative data within the itsourcecode Online Enrollment System 1.0. This could result in data breaches, financial loss, and reputational damage for institutions using the vulnerable software. Given the availability of a public exploit, a large number of educational institutions are potentially at risk. The impact includes unauthorized access to student records, modification of grades, and potentially complete system takeover.

## Recommendation

*   Deploy the Sigma rule `Detect SQL Injection in Online Enrollment System` to identify exploitation attempts against vulnerable `index.php` endpoints based on HTTP GET request parameters.
*   Inspect web server logs for requests to `/sms/user/index.php` containing suspicious SQL syntax in the `id` parameter (e.g., `UNION SELECT`, `SLEEP()`) to detect ongoing attacks.
*   Apply input validation and sanitization to the `USERID` parameter in the `/sms/user/index.php` script to prevent SQL injection, as detailed in CVE-2026-5534.
*   Block access to the malicious URLs listed in the IOCs table at the network perimeter to prevent initial access.
