---
title: Bootstrapy CMS Unauthenticated SQL Injection Vulnerabilities
slug: 2026-03-bootstrapy-sqli
description: Bootstrapy CMS contains multiple SQL injection vulnerabilities that allow unauthenticated attackers to execute arbitrary SQL queries by injecting malicious code through POST parameters to extract sensitive database information or cause denial of service.
date: "2026-03-24T12:16:06Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - bootstrapy-cms
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25642
  - https://www.exploit-db.com/exploits/46590
  - https://www.vulncheck.com/advisories/bootstrapy-cms-lastest-multiple-sql-injection-via-forum-and-contact-modules
iocs:
  - type: url
    value: http://bootstrapy.com
  - type: url
    value: https://www.exploit-db.com/exploits/46590
  - type: url
    value: https://www.vulncheck.com/advisories/bootstrapy-cms-lastest-multiple-sql-injection-via-forum-and-contact-modules
ioc_counts:
  url: 3
rules:
  - title: Detect SQL Injection Attempt in Bootstrapy CMS forum-thread.php
    description: Detects potential SQL injection attempts in Bootstrapy CMS by monitoring POST requests to forum-thread.php with suspicious SQL syntax in the thread_id parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempt in Bootstrapy CMS contact-submit.php
    description: Detects potential SQL injection attempts in Bootstrapy CMS by monitoring POST requests to contact-submit.php with suspicious SQL syntax in the subject parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Attempt in Bootstrapy CMS post-new-submit.php
    description: Detects potential SQL injection attempts in Bootstrapy CMS by monitoring POST requests to post-new-submit.php with suspicious SQL syntax in the post-id parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 3
---

Bootstrapy CMS is vulnerable to multiple SQL injection vulnerabilities (CVE-2019-25642). These vulnerabilities allow unauthenticated attackers to execute arbitrary SQL queries. The attack vector involves injecting malicious SQL code via POST parameters in specific PHP files: `forum-thread.php`, `contact-submit.php`, and `post-new-submit.php`. Successful exploitation can lead to sensitive database information disclosure or a denial-of-service condition. The identified vulnerabilities exist in the latest version of Bootstrapy CMS as of March 2026, and the exploitation does not require any authentication. This poses a significant threat to organizations using this CMS.

## Attack Chain

1.  An unauthenticated attacker identifies a Bootstrapy CMS instance.
2.  The attacker crafts a malicious HTTP POST request targeting one of the vulnerable PHP files: `forum-thread.php`, `contact-submit.php`, or `post-new-submit.php`.
3.  The attacker injects a SQL payload into the `thread_id` parameter of `forum-thread.php`, the `subject` parameter of `contact-submit.php`, or the `post-id` parameter of `post-new-submit.php`.
4.  The web server processes the request, passing the injected SQL payload to the database.
5.  The database executes the malicious SQL query, potentially allowing the attacker to read sensitive data.
6.  The attacker retrieves sensitive data from the database, such as user credentials, configuration settings, or other confidential information.
7.  Alternatively, the attacker injects a SQL payload designed to cause a denial-of-service condition by consuming excessive database resources.
8.  The attacker disrupts the availability of the Bootstrapy CMS instance.

## Impact

Successful exploitation of these SQL injection vulnerabilities can lead to the complete compromise of the Bootstrapy CMS database. This may include the theft of sensitive user data, modification of website content, or complete denial of service. The impact is high because it affects the confidentiality, integrity, and availability of the application and its data. The number of affected installations is unknown, but any organization running a vulnerable version of Bootstrapy CMS is at risk.

## Recommendation

*   Inspect web server logs for HTTP POST requests to `forum-thread.php`, `contact-submit.php`, and `post-new-submit.php` containing suspicious SQL syntax in the `thread_id`, `subject`, or `post-id` parameters, as covered by the Sigma rules below.
*   Apply available patches from the vendor to remediate CVE-2019-25642.
*   Block access to the known exploit URLs in the IOC list at your web application firewall (WAF).
*   Implement input validation and sanitization for all user-supplied data to prevent SQL injection attacks.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
