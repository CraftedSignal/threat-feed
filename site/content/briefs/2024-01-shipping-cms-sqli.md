---
title: Shipping System CMS 1.0 Authentication Bypass via SQL Injection
slug: 2024-01-shipping-cms-sqli
description: Shipping System CMS 1.0 is vulnerable to SQL injection, allowing unauthenticated attackers to bypass authentication by injecting SQL code through the username parameter.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - authentication-bypass
  - web-application
vendors:
  - wecodex
products:
  - Shipping System CMS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25183
  - https://www.exploit-db.com/exploits/44722
  - https://www.vulncheck.com/advisories/shipping-system-cms-sql-injection-via-admin-login
  - https://www.wecodex.com/item/view/shipping-system-by-parcel-in-php-and-mysql/4
rules:
  - title: Detect Shipping System CMS SQL Injection Attempt
    description: Detects potential SQL injection attempts against Shipping System CMS login endpoint by looking for specific SQL keywords in the username parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Shipping System CMS Login POST Request
    description: Detects POST requests to the Shipping System CMS admin login page.
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

Shipping System CMS 1.0 is susceptible to SQL injection attacks, specifically targeting the authentication process. This vulnerability, identified as CVE-2018-25183, allows unauthenticated attackers to bypass the login mechanism by injecting malicious SQL code into the username parameter. The attack leverages boolean-based blind SQL injection techniques, enabling attackers to authenticate without providing valid credentials. Successful exploitation grants unauthorized access to administrative functionalities of the CMS, posing a significant risk to data confidentiality, integrity, and availability. This vulnerability was published in 2026.

## Attack Chain

1.  Attacker sends a POST request to the `/admin/login` endpoint.
2.  The POST request includes a crafted `username` parameter containing a malicious SQL payload designed for boolean-based blind injection.
3.  The application processes the injected SQL code without proper sanitization or parameterization.
4.  The injected SQL code manipulates the authentication query to return true, regardless of the actual username and password.
5.  The application incorrectly authenticates the attacker based on the manipulated query results.
6.  The attacker gains unauthorized access to the administrative panel of Shipping System CMS 1.0.
7.  Attacker exploits their access to modify system configurations, access sensitive data, or perform other malicious activities.

## Impact

Successful exploitation of this SQL injection vulnerability leads to complete authentication bypass, granting attackers full administrative control over affected Shipping System CMS 1.0 instances. This can result in unauthorized data access, modification, or deletion, potentially leading to significant financial loss, reputational damage, and disruption of shipping operations. The vulnerability has a CVSS v3.1 score of 8.2, indicating a high severity.

## Recommendation

*   Deploy the Sigma rule `Detect Shipping System CMS SQL Injection Attempt` to your SIEM to identify potential exploitation attempts targeting the login endpoint.
*   Inspect web server logs for suspicious POST requests to the `/admin/login` endpoint with unusual characters or SQL keywords in the `username` parameter to detect SQL injection attempts (webserver logs).
*   Apply input validation and sanitization to the `username` parameter in Shipping System CMS 1.0, or upgrade to a patched version if available, to prevent SQL injection (CVE-2018-25183).
