---
title: SQL Injection Vulnerability in Simple Content Management System 1.0
slug: 2026-04-simple-cms-sqli
description: A remote SQL injection vulnerability exists in code-projects Simple Content Management System 1.0, specifically affecting the /web/admin/login.php file where manipulation of the 'User' argument allows unauthenticated attackers to execute arbitrary SQL queries.
date: "2026-04-13T15:17:49Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - sqli
  - web-application
  - cve-2026-6182
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6182
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6182
  - https://code-projects.org/
  - https://github.com/Xmyronn/simple-cms-sqli-login-bypass-CVE-HUNT-
  - https://vuldb.com/submit/797263
  - https://vuldb.com/vuln/357105
  - https://vuldb.com/vuln/357105/cti
iocs:
  - type: url
    value: https://code-projects.org/
  - type: url
    value: https://github.com/Xmyronn/simple-cms-sqli-login-bypass-CVE-HUNT-
  - type: url
    value: https://vuldb.com/submit/797263
  - type: url
    value: https://vuldb.com/vuln/357105
  - type: url
    value: https://vuldb.com/vuln/357105/cti
ioc_counts:
  url: 5
rules:
  - title: Detect SQL Injection Attempts in Simple CMS Login
    description: Detects potential SQL injection attempts in requests to the /web/admin/login.php endpoint by looking for common SQL keywords in the User parameter.
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
  - title: Detect Simple CMS SQL Injection Errors
    description: Detects potential SQL injection errors by analyzing web server logs for specific error messages related to database interactions in the /web/admin/login.php endpoint.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability has been identified in code-projects Simple Content Management System (CMS) version 1.0. The vulnerability resides in the `/web/admin/login.php` file and stems from improper sanitization of user-supplied input within the `User` argument. An unauthenticated, remote attacker can exploit this vulnerability to inject arbitrary SQL commands, potentially leading to unauthorized data access, modification, or deletion. Publicly available exploits exist, increasing the risk of widespread exploitation. Given the simplicity of the targeted software, many small businesses or personal websites could be running vulnerable instances.

## Attack Chain

1.  The attacker identifies a publicly accessible instance of Simple Content Management System 1.0.
2.  The attacker crafts a malicious HTTP request targeting the `/web/admin/login.php` endpoint.
3.  The crafted request includes a SQL injection payload within the `User` parameter.
4.  The application fails to properly sanitize the input, passing the malicious payload to the database.
5.  The database executes the injected SQL commands, allowing the attacker to bypass authentication.
6.  The attacker gains unauthorized administrative access to the CMS.
7.  The attacker modifies the CMS content or extracts sensitive data from the database.
8.  The attacker may install a web shell for persistent access and further exploitation.

## Impact

Successful exploitation of this vulnerability grants attackers unauthorized access to the Simple Content Management System 1.0. This can lead to sensitive data exfiltration, modification of website content (defacement), or complete takeover of the underlying server. The vulnerable software is likely used by individuals or small businesses, potentially leading to a significant impact on their online presence and data security. Given the public availability of exploits, mass exploitation is a realistic threat.

## Recommendation

*   Inspect web server logs for requests to `/web/admin/login.php` containing suspicious characters or SQL keywords in the `User` parameter to detect potential exploitation attempts (see rule: "Detect SQL Injection Attempts in Simple CMS Login").
*   Monitor web server logs for unusual database errors originating from `/web/admin/login.php`, which may indicate successful SQL injection (see rule: "Detect Simple CMS SQL Injection Errors").
*   Implement input validation and sanitization on all user-supplied data, particularly within the `/web/admin/login.php` script, to prevent SQL injection attacks.
*   Organizations using code-projects Simple Content Management System 1.0 should consider migrating to a more secure platform or applying security patches if available from the vendor.
