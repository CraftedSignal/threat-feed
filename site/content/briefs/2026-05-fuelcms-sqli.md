---
title: Fuel CMS 1.4.13 Blind SQL Injection Vulnerability (CVE-2021-47980)
slug: 2026-05-fuelcms-sqli
description: Fuel CMS 1.4.13 is vulnerable to blind SQL injection via the 'col' parameter in the Activity Log interface, allowing authenticated attackers to manipulate database queries and extract information through time-based delays (CVE-2021-47980).
date: "2026-05-16T16:23:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - cve-2021-47980
  - sql-injection
  - web-application
vendors:
  - Daylight Studio
products:
  - Fuel CMS 1.4.13
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2021-47980
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47980
  - https://github.com/daylightstudio/FUEL-CMS/archive/1.4.13.zip
  - https://www.exploit-db.com/exploits/50523
  - https://www.getfuelcms.com/
  - https://www.vulncheck.com/advisories/fuel-cms-blind-sql-injection-via-col-parameter
rules:
  - title: Detects CVE-2021-47980 Exploitation — Fuel CMS Activity Log SQL Injection Attempt
    description: Detects CVE-2021-47980 exploitation — SQL injection attempts in the 'col' parameter of requests to the Fuel CMS Activity Log interface.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2021-47980 Exploitation — Fuel CMS Activity Log SQL Injection Attempt (Time Based)
    description: Detects CVE-2021-47980 exploitation — Time-based SQL injection attempts in the 'col' parameter of requests to the Fuel CMS Activity Log interface.
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

Fuel CMS 1.4.13 is susceptible to a blind SQL injection vulnerability (CVE-2021-47980) within the Activity Log interface. This flaw allows authenticated attackers to inject arbitrary SQL code into the 'col' parameter of requests to the logs endpoint. Successful exploitation enables attackers to manipulate database queries and potentially extract sensitive information from the database by observing response time delays. The vulnerability exists due to insufficient input sanitization of the 'col' parameter when constructing SQL queries. Defenders should implement detection and prevention measures to mitigate the risk of unauthorized data access.

## Attack Chain

1.  An authenticated attacker logs into the Fuel CMS application.
2.  The attacker navigates to the Activity Log interface.
3.  The attacker crafts a malicious HTTP request targeting the logs endpoint, injecting SQL code into the 'col' parameter. The attacker crafts SQL injection payloads designed to cause time delays based on conditional logic.
4.  The attacker sends the crafted HTTP request to the server.
5.  The Fuel CMS application processes the request without proper sanitization of the 'col' parameter, incorporating the malicious SQL code into a database query.
6.  The database executes the injected SQL code.
7.  The attacker monitors the response time from the server. By analyzing the timing, the attacker infers the results of the injected SQL queries, effectively extracting data bit by bit.
8. The attacker repeats this process, refining the SQL injection payloads to extract additional database information such as usernames, passwords, or other sensitive data.

## Impact

Successful exploitation of this blind SQL injection vulnerability (CVE-2021-47980) could allow an attacker to extract sensitive information from the Fuel CMS database. This information could include user credentials, configuration details, and other confidential data. The impact includes potential data breaches, unauthorized access to the system, and further compromise of the application and its underlying infrastructure.

## Recommendation

*   Deploy the Sigma rule designed to detect SQL injection attempts in HTTP requests targeting the logs endpoint in Fuel CMS to identify exploitation attempts (see rule below).
*   Apply input validation and sanitization to the 'col' parameter in the Activity Log interface to prevent SQL injection, according to secure coding practices.
*   Monitor web server logs for suspicious activity, such as unusual requests to the logs endpoint with potentially malicious SQL syntax in the 'col' parameter.
*   Upgrade Fuel CMS to a patched version that addresses CVE-2021-47980, if available from the vendor.
