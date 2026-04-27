---
title: Wecodex Hotel CMS 1.0 SQL Injection Vulnerability
slug: 2026-03-wecodex-sqli
description: Wecodex Hotel CMS 1.0 is vulnerable to SQL injection in the admin login functionality, allowing unauthenticated attackers to bypass authentication and potentially extract sensitive database information or gain administrative access by injecting SQL code through the username parameter in POST requests to index.php with action=processlogin.
date: "2026-03-26T12:16:04Z"
severities:
  - critical
tags:
  - sqli
  - web-application
  - authentication-bypass
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25195
  - https://www.exploit-db.com/exploits/44729
  - https://www.vulncheck.com/advisories/wecodex-hotel-cms-sql-injection-via-admin-login
rules:
  - title: Detect Wecodex Hotel CMS SQL Injection Attempt via Login
    description: Detects potential SQL injection attempts targeting the Wecodex Hotel CMS login functionality based on suspicious SQL syntax in the POST data.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection in POST Request
    description: Detects suspicious SQL injection attempts in POST requests by searching for common SQL syntax.
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

Wecodex Hotel CMS 1.0 is susceptible to an SQL injection vulnerability (CVE-2018-25195) within its admin login feature. Discovered in 2026, this flaw enables unauthenticated attackers to inject malicious SQL code into the 'username' parameter of a POST request sent to the 'index.php' page with the 'action=processlogin' parameter. Successful exploitation could lead to the bypass of authentication mechanisms, potentially granting unauthorized administrative privileges. The vulnerability poses a…
