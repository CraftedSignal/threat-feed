---
title: Adianti Framework SQL Injection Vulnerability (CVE-2018-25257)
slug: 2024-01-adianti-sql-injection
description: Adianti Framework versions 5.5.0 and 5.6.0 are vulnerable to SQL injection via the SystemProfileForm name field, allowing authenticated users to manipulate database queries, modify user credentials, and potentially gain administrative access.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - adianti-framework
vendors:
  - Adianti
products:
  - Adianti Framework
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25257
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25257
  - https://www.exploit-db.com/exploits/46217
  - https://www.vulncheck.com/advisories/adianti-framework-and-sql-injection-via-profile
rules:
  - title: Detect Adianti Framework SQL Injection Attempt
    description: Detects potential SQL injection attempts against Adianti Framework's SystemProfileForm by monitoring for suspicious SQL syntax in the cs-uri-query.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Adianti Framework Profile Update with Suspicious Characters
    description: This rule detects suspicious profile update attempts in Adianti Framework by looking for special characters and SQL keywords in the request.
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

Adianti Framework, a PHP-based web application framework, versions 5.5.0 and 5.6.0 are susceptible to SQL injection (CVE-2018-25257). The vulnerability resides in the SystemProfileForm, specifically within the 'name' field. An authenticated user can inject arbitrary SQL code through this field, leading to potential unauthorized data access or modification. This flaw could be exploited to escalate privileges, potentially granting an attacker administrative control over the affected application. Given the potential for complete system compromise, organizations using these versions of the Adianti Framework should take immediate action to mitigate this risk.

## Attack Chain

1. An attacker gains valid user credentials for the Adianti Framework application.
2. The attacker navigates to the SystemProfileForm page, typically used for editing user profile information.
3. In the 'name' field, the attacker crafts a malicious SQL injection payload. This payload is designed to modify the database query used to update the user profile.
4. The attacker submits the form with the injected SQL code.
5. The application processes the request, executing the attacker-controlled SQL query against the database.
6. The injected SQL code modifies user credentials within the database, potentially granting administrative privileges to the attacker's account or other accounts.
7. The attacker logs in with the compromised administrative account.
8. The attacker leverages their elevated privileges to perform malicious actions such as data exfiltration, system modification, or further compromise of the underlying infrastructure.

## Impact

Successful exploitation of this SQL injection vulnerability allows attackers to gain unauthorized access to sensitive data, modify user accounts, and potentially gain full administrative control of the Adianti Framework application. This can lead to data breaches, service disruption, and reputational damage. The vulnerability affects versions 5.5.0 and 5.6.0 of the Adianti Framework. The number of affected installations is currently unknown.

## Recommendation

*   Upgrade to a patched version of the Adianti Framework that addresses CVE-2018-25257.
*   Deploy the provided Sigma rule "Detect Adianti Framework SQL Injection Attempt" to monitor web server logs for potential exploitation attempts.
*   Implement input validation and sanitization on all user-supplied data within the Adianti Framework, particularly on the 'name' field in SystemProfileForm, to prevent SQL injection attacks.
*   Restrict database access privileges to the minimum necessary for the application to function correctly.
