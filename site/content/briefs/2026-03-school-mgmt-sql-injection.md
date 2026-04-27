---
title: School Management System CMS 1.0 SQL Injection Vulnerability
slug: 2026-03-school-mgmt-sql-injection
description: School Management System CMS 1.0 is vulnerable to SQL injection in the admin login functionality, allowing attackers to bypass authentication by injecting SQL code through the username parameter.
date: "2026-03-26T12:16:04Z"
severities:
  - critical
tags:
  - sql-injection
  - web-application
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25201
  - https://www.exploit-db.com/exploits/44727
  - https://www.vulncheck.com/advisories/school-management-system-cms-admin-login-sql-injection
  - https://www.wecodex.com/item/view/school-management-system-in-php-and-mysql/5
rules:
  - title: Detect SQL Injection Attempts in School Management System CMS Login
    description: Detects potential SQL injection attempts targeting the /processlogin endpoint in School Management System CMS.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Blind SQL Injection in School Management System CMS
    description: Detects boolean-based blind SQL injection patterns in requests to the /processlogin endpoint, indicative of potential exploitation attempts.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

School Management System CMS 1.0 is vulnerable to SQL injection affecting the admin login functionality. Disclosed in March 2026, the vulnerability allows unauthenticated attackers to bypass the login mechanism and gain administrative access by injecting malicious SQL code into the username parameter of the processlogin endpoint. The vulnerability stems from improper sanitization of user-supplied input, enabling boolean-based blind SQL injection. Successful exploitation grants full…
