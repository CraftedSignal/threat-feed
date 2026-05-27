---
title: OpenCATS 0.9.7.4 SQL Injection Vulnerability
slug: 2026-05-opencats-sqli
description: A SQL Injection vulnerability exists in OpenCATS 0.9.7.4, with a published exploit that allows for database version and user extraction on unpatched systems.
date: "2026-05-27T12:51:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - webapps
  - opencats
vendors:
  - OpenCATS
products:
  - OpenCATS 0.9.7.4
affected_os:
  - Ubuntu 22.04
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://www.exploit-db.com/exploits/52579
  - https://github.com/opencats/OpenCATS
rules:
  - title: Detect OpenCATS SQL Injection Attempt via getDataGridPager
    description: Detects SQL injection attempts in OpenCATS 0.9.7.4 via the getDataGridPager function by identifying unusual parameters within the ajax.php request.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect OpenCATS Default Credentials Login Attempt
    description: Detects login attempts to OpenCATS with the default credentials (admin/cats), indicating potential brute-force or exploit attempts.
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

A SQL Injection vulnerability has been identified in OpenCATS version 0.9.7.4. A public exploit (EDB-52579) is available on Exploit-DB, significantly increasing the risk to systems running this version. The exploit, tested on Ubuntu 22.04 with Apache2, PHP, and MariaDB 10.6, leverages a flaw in the getDataGridPager function to inject SQL commands. This allows an attacker to potentially extract sensitive information, including database version details, usernames, access levels, and password hashes, thereby compromising the application's security. The availability of a working exploit makes it crucial for organizations using OpenCATS 0.9.7.4 to apply necessary patches or mitigations immediately.

## Attack Chain

1.  An attacker gains initial access to the OpenCATS application.
2.  The attacker authenticates to the application, using default credentials if available (admin/cats).
3.  The attacker crafts a malicious HTTP GET request to the `ajax.php` endpoint, specifically targeting the `getDataGridPager` function.
4.  Within the parameters of `getDataGridPager`, the attacker injects SQL code into the `sortDirection` parameter. This is achieved by manipulating the JSON-encoded parameters passed to the function.
5.  The injected SQL code is designed to exploit a blind SQL Injection vulnerability, using `DESC,IF(({cond}),SLEEP({delay}),0)`.
6.  The attacker uses conditional statements and `SLEEP()` functions to infer data based on response times. This allows them to bypass traditional output-based SQL injection protections.
7.  The attacker extracts the database version, usernames, access levels, and password hashes from the database.
8.  The attacker uses the extracted credentials and information to further compromise the system or gain unauthorized access to sensitive data.

## Impact

Successful exploitation of this SQL Injection vulnerability can lead to full database compromise. An attacker could potentially extract sensitive information such as usernames, passwords, and other confidential data stored within the OpenCATS database. This could result in unauthorized access to the application, data breaches, and potential reputational damage. The vulnerability targets any system running OpenCATS 0.9.7.4, making it a widespread risk for users of this software.

## Recommendation

*   Apply available patches or updates for OpenCATS to address the SQL Injection vulnerability.
*   Monitor web server logs for suspicious GET requests to `ajax.php` with unusual parameters in the `f` and `p` parameters, using the Sigma rule provided.
*   Implement a web application firewall (WAF) rule to filter out SQL injection attempts targeting the `sortDirection` parameter in `getDataGridPager`.
*   Enforce strong password policies and multi-factor authentication to mitigate the impact of compromised credentials, based on extracted password hashes.
*   Deploy the Sigma rule to detect SQL injection attempts via `ajax.php` and tune it to your specific environment.
