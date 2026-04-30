---
title: code-projects Online FIR System SQL Injection Vulnerability
slug: 2026-04-online-fir-sqli
description: A SQL injection vulnerability in code-projects Online FIR System 1.0 allows remote attackers to execute arbitrary SQL commands by manipulating the email or password parameters in the /Login/checklogin.php file.
date: "2026-04-06T16:16:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - cve-2026-5665
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-5665
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5665
  - https://code-projects.org/
  - https://github.com/ahmadmarz10-hub/CVEsMarz/blob/main/SQL%20Injection%20in%20Online%20FIR%20System%20PHP%20email%20Parameter.md
  - https://vuldb.com/submit/786310
  - https://vuldb.com/vuln/355488
  - https://vuldb.com/vuln/355488/cti
iocs:
  - type: url
    value: https://code-projects.org/
  - type: url
    value: https://github.com/ahmadmarz10-hub/CVEsMarz/blob/main/SQL%20Injection%20in%20Online%20FIR%20System%20PHP%20email%20Parameter.md
  - type: url
    value: https://vuldb.com/submit/786310
  - type: url
    value: https://vuldb.com/vuln/355488
  - type: url
    value: https://vuldb.com/vuln/355488/cti
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
  url: 5
rules:
  - title: Detect SQL Injection Attempts in Online FIR System Login
    description: Detects potential SQL injection attempts targeting the /Login/checklogin.php endpoint by searching for common SQL injection keywords in the email or password parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Exploitation of code-projects Online FIR System SQL Injection
    description: Detects possible exploitation of the SQL Injection vulnerability in code-projects Online FIR System 1.0
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

A SQL injection vulnerability has been identified in code-projects Online FIR System version 1.0. The vulnerability resides within the `/Login/checklogin.php` file, specifically affecting the login component. An attacker can remotely exploit this vulnerability by manipulating the `email` or `password` parameters within a request. The vulnerability has been assigned CVE-2026-5665 and given a CVSS v3.1 score of 7.3, indicating a high severity. Public exploits exist, meaning defenders should prioritize detection and mitigation measures. This vulnerability poses a significant risk to organizations using the affected software, as successful exploitation could lead to data breaches, account takeover, or other unauthorized access.

## Attack Chain

1.  An attacker identifies a vulnerable instance of code-projects Online FIR System 1.0.
2.  The attacker crafts a malicious HTTP request targeting the `/Login/checklogin.php` endpoint.
3.  The request includes SQL injection payloads within the `email` or `password` parameters.
4.  The application fails to properly sanitize the input, passing the malicious payload to the database.
5.  The database executes the injected SQL code, allowing the attacker to read, modify, or delete data.
6.  The attacker may extract sensitive information such as user credentials or financial records.
7.  The attacker could use the extracted credentials to gain unauthorized access to user accounts.
8.  The attacker could escalate privileges within the system, potentially gaining full control of the application and underlying server.

## Impact

Successful exploitation of this SQL injection vulnerability can have severe consequences. An attacker could gain unauthorized access to sensitive data, including user credentials, personal information, and financial records. This can lead to identity theft, financial loss, and reputational damage. The number of potential victims depends on the number of installations of the vulnerable Online FIR System. The targeted sectors are unknown, but any organization using this system is at risk.

## Recommendation

*   Inspect web server logs for suspicious POST requests to `/Login/checklogin.php` containing SQL injection attempts using the provided Sigma rule.
*   Apply input validation and sanitization to the `email` and `password` parameters in `/Login/checklogin.php` to prevent SQL injection.
*   Monitor network traffic for connections to or from the known malicious URLs listed in the IOC table.
*   Consider implementing a web application firewall (WAF) rule to block known SQL injection patterns.
