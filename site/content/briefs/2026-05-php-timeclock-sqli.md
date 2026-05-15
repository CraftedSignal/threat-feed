---
title: PHP Timeclock 1.04 Unauthenticated SQL Injection Vulnerability
slug: 2026-05-php-timeclock-sqli
description: PHP Timeclock 1.04 is vulnerable to time-based and boolean-based blind SQL injection in the login_userid parameter of login.php, allowing unauthenticated attackers to extract sensitive database information by sending crafted POST requests with SQL payloads.
date: "2026-05-15T19:20:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - web-application
  - php
vendors:
  - SourceForge
products:
  - PHP Timeclock
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2021-47966
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47966
  - http://timeclock.sourceforge.net
  - https://sourceforge.net/projects/timeclock/files/PHP%20Timeclock/PHP%20Timeclock%201.04/
  - https://www.exploit-db.com/exploits/49849
  - https://www.vulncheck.com/advisories/php-timeclock-sql-injection-via-login-php
rules:
  - title: Detects CVE-2021-47966 Exploitation — PHP Timeclock SQL Injection Attempt
    description: Detects CVE-2021-47966 exploitation attempt via SQL injection in the login_userid parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2021-47966 Exploitation — PHP Timeclock UNION SELECT SQL Injection
    description: Detects CVE-2021-47966 exploitation attempt via UNION SELECT injection in the login_userid parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

PHP Timeclock 1.04 is susceptible to SQL injection vulnerabilities, specifically time-based and boolean-based blind SQL injection. The vulnerability resides in the `login_userid` parameter of the `login.php` script. Unauthenticated attackers can exploit this flaw by injecting malicious SQL code into the vulnerable parameter, enabling them to extract sensitive information from the database. This includes employee names and credentials, potentially leading to unauthorized access and data breaches. The attack involves crafting specific POST requests containing SQL payloads designed to leverage `SLEEP` functions or `RLIKE` conditional statements to infer database contents.

## Attack Chain

1. An unauthenticated attacker identifies the login form at `login.php`.
2. The attacker crafts a malicious POST request targeting the `login_userid` parameter.
3. The POST request contains a SQL payload designed to exploit the blind SQL injection vulnerability, using `SLEEP` functions (time-based) or `RLIKE` conditional statements (boolean-based).
4. The server processes the SQL payload within the `login_userid` parameter.
5. Based on the response time (time-based) or the boolean result (boolean-based), the attacker infers information about the database structure and contents.
6. The attacker iteratively refines the SQL payloads to extract more data.
7. Sensitive information, such as employee usernames and passwords, is extracted from the database.

## Impact

Successful exploitation of this SQL injection vulnerability allows attackers to extract sensitive database information, including employee credentials and personal data. This can lead to unauthorized access to the system, data breaches, and potential compromise of employee accounts. The vulnerability affects PHP Timeclock 1.04, potentially impacting any organization using this software to manage employee time tracking. The CVSS v3.1 base score is 8.2, indicating a high severity.

## Recommendation

*   Apply available patches or upgrade to a secure version of PHP Timeclock to remediate CVE-2021-47966.
*   Deploy the Sigma rule to detect SQL injection attempts against the `login_userid` parameter in `login.php`.
*   Monitor web server logs for suspicious POST requests containing SQL syntax, specifically `SLEEP` and `RLIKE` functions.
*   Implement input validation and sanitization on the `login_userid` parameter to prevent SQL injection attacks.
