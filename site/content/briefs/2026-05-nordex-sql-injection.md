---
title: Nordex N149/4.0-4.5 Wind Turbine Web Server SQL Injection Vulnerability (CVE-2018-25333)
slug: 2026-05-nordex-sql-injection
description: Nordex N149/4.0-4.5 Wind Turbine Web Server 4.0 is vulnerable to SQL injection (CVE-2018-25333), allowing unauthenticated attackers to execute arbitrary SQL queries and extract sensitive information via crafted POST requests to login.php.
date: "2026-05-17T13:19:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2018-25333
  - webserver
  - industrial-control-system
vendors:
  - Nordex
products:
  - N149/4.0-4.5 Wind Turbine Web Server 4.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25333
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25333
  - http://www.nordex-online.com
  - https://www.exploit-db.com/exploits/44684
  - https://www.vulncheck.com/advisories/nordex-n149-wind-turbine-web-server-sql-injection
rules:
  - title: Detect Nordex Wind Turbine SQL Injection Attempt
    description: Detects CVE-2018-25333 exploitation — SQL injection attempts targeting the login.php endpoint on Nordex wind turbine web servers via POST requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1202
    data_sources:
      - webserver
  - title: Detect Nordex Wind Turbine Authentication Bypass via SQL Injection
    description: Detects CVE-2018-25333 exploitation — successful authentication bypass on Nordex wind turbine web servers after a possible SQL injection attempt.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1202
    data_sources:
      - webserver
rules_count: 2
---

Nordex N149/4.0-4.5 Wind Turbine Web Server 4.0 is susceptible to a critical SQL injection vulnerability, identified as CVE-2018-25333. An unauthenticated attacker can exploit this flaw by injecting malicious SQL code into the login parameter of the login.php script. This allows the attacker to bypass authentication, execute arbitrary SQL queries, potentially gaining unauthorized access to sensitive data within the turbine's web server database. The vulnerability was reported in May 2026. Successful exploitation could lead to a full compromise of the wind turbine's control systems, enabling attackers to manipulate operational settings and potentially cause physical damage.

## Attack Chain

1.  Attacker identifies a Nordex N149/4.0-4.5 Wind Turbine Web Server 4.0 running a vulnerable version of the web server software.
2.  Attacker crafts a malicious HTTP POST request targeting the `login.php` endpoint.
3.  The crafted POST request includes an SQL injection payload within the `login` parameter.
4.  The web server processes the POST request without properly sanitizing the `login` parameter, allowing the SQL injection payload to be executed.
5.  The injected SQL code executes arbitrary SQL queries against the database, potentially extracting sensitive information such as usernames, passwords, or configuration data.
6.  The attacker uses the extracted credentials or the ability to execute arbitrary queries to bypass authentication mechanisms.
7.  Attacker gains unauthorized access to the wind turbine's control panel.
8.  The attacker manipulates operational settings, potentially causing the turbine to malfunction or shut down, or exfiltrates proprietary data.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2018-25333) can lead to a full compromise of the affected Nordex N149/4.0-4.5 Wind Turbine Web Server 4.0. Attackers can extract sensitive database information, bypass authentication, and gain unauthorized control over the wind turbine's operational settings. This can result in financial losses due to downtime, physical damage to the turbine, and potential safety hazards. While the number of affected installations is not specified, this vulnerability poses a significant risk to organizations operating Nordex wind turbines.

## Recommendation

*   Apply the vendor-provided patch or upgrade to a secure version of the Nordex N149/4.0-4.5 Wind Turbine Web Server to remediate CVE-2018-25333.
*   Deploy the Sigma rule "Detect Nordex Wind Turbine SQL Injection Attempt" to monitor for POST requests with SQL injection attempts targeting the login.php endpoint.
*   Implement web application firewall (WAF) rules to filter out malicious SQL injection payloads in HTTP POST requests targeting the login.php endpoint.
*   Conduct regular security audits and penetration testing on wind turbine systems to identify and address potential vulnerabilities.
