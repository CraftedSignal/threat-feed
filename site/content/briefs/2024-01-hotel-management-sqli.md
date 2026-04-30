---
title: SourceCodester Hotel Management System SQL Injection Vulnerability
slug: 2024-01-hotel-management-sqli
description: A SQL injection vulnerability exists in SourceCodester Hotel Management System 1.0 in the /index.php/reservation/check component due to improper sanitization of the room_type parameter, allowing a remote attacker to execute arbitrary SQL commands.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - vulnerability
  - web application
vendors:
  - SourceCodester
products:
  - Hotel Management System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7506
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7506
rules:
  - title: Detect SQL Injection Attempts in Hotel Management System
    description: Detects potential SQL injection attempts targeting the /index.php/reservation/check endpoint by monitoring for suspicious characters and SQL keywords in the cs-uri-query.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Payloads in HTTP Requests
    description: This rule detects potential SQL injection attacks by identifying common SQL keywords and syntax within HTTP request parameters.
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

SourceCodester Hotel Management System version 1.0 is vulnerable to SQL injection. The vulnerability is located in the `/index.php/reservation/check` endpoint. Specifically, the `room_type` parameter is not properly sanitized, allowing for the injection of malicious SQL queries. This vulnerability can be exploited remotely and has been publicly disclosed, making it accessible to a wide range of threat actors. Successful exploitation allows attackers to read, modify, or delete sensitive data within the application's database. This could lead to unauthorized access, data breaches, and potential disruption of hotel operations.

## Attack Chain

1.  An attacker identifies a vulnerable instance of SourceCodester Hotel Management System 1.0.
2.  The attacker crafts a malicious HTTP GET or POST request targeting the `/index.php/reservation/check` endpoint.
3.  The malicious request includes a SQL injection payload within the `room_type` parameter.
4.  The application processes the request without proper sanitization of the `room_type` parameter.
5.  The injected SQL code is executed against the application's database.
6.  The attacker extracts sensitive information from the database, such as user credentials, reservation details, or financial data.
7.  The attacker may use the extracted credentials to gain unauthorized access to administrative panels.
8.  The attacker may further compromise the system by modifying data, creating rogue accounts, or planting malicious code.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to significant data breaches, impacting both the hotel and its customers. Sensitive customer data, including personal information, reservation details, and payment information, could be exposed. The vulnerability could allow attackers to gain administrative access to the Hotel Management System, leading to further compromise of the system and potential disruption of hotel operations. Depending on the database configuration, the attacker may even be able to execute commands on the underlying operating system.

## Recommendation

*   Deploy the provided Sigma rule to detect SQL injection attempts targeting the `/index.php/reservation/check` endpoint in web server logs.
*   Implement input validation and sanitization for all user-supplied input, especially the `room_type` parameter, to prevent SQL injection attacks.
*   Patch or upgrade to a secure version of SourceCodester Hotel Management System that addresses this SQL injection vulnerability. If a patch is unavailable, consider implementing a web application firewall (WAF) rule to filter out malicious requests.
*   Review and harden database security configurations to limit the privileges of the database user account used by the application.
