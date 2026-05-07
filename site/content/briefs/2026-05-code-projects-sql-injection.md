---
title: code-projects Feedback System 1.0 SQL Injection Vulnerability (CVE-2026-8098)
slug: 2026-05-code-projects-sql-injection
description: A SQL injection vulnerability exists in code-projects Feedback System 1.0 via manipulation of the email parameter in /admin/checklogin.php, potentially allowing remote attackers to execute arbitrary SQL commands.
date: "2026-05-07T21:16:30Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - cve
  - sql-injection
  - web-application
vendors:
  - code-projects
products:
  - Feedback System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-8098
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8098
  - https://code-projects.org/
  - https://github.com/redshadowword-cell/CVE/issues/3
  - https://vuldb.com/submit/808126
  - https://vuldb.com/vuln/361851
  - https://vuldb.com/vuln/361851/cti
rules:
  - title: Detect CVE-2026-8098 Exploitation — SQL Injection in code-projects Feedback System
    description: Detects CVE-2026-8098 exploitation — HTTP POST to /admin/checklogin.php with SQL injection attempts in the email parameter
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1211
    data_sources:
      - webserver
  - title: Detect Suspicious SQL Error Messages
    description: Detects possible SQL injection attempts by looking for SQL error messages in the web server logs.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1211
    data_sources:
      - webserver
rules_count: 2
---

A SQL injection vulnerability, identified as CVE-2026-8098, has been discovered in code-projects Feedback System version 1.0. The vulnerability resides in the `/admin/checklogin.php` file and can be exploited by manipulating the `email` argument. This allows for the injection of arbitrary SQL commands. The vulnerability is remotely exploitable, and a public exploit is available, increasing the risk of potential attacks. This vulnerability poses a significant threat to systems running the affected software, potentially leading to data breaches, unauthorized access, and complete system compromise.

## Attack Chain

1.  Attacker identifies a vulnerable code-projects Feedback System 1.0 instance.
2.  Attacker crafts a malicious HTTP request targeting `/admin/checklogin.php`.
3.  The HTTP request includes a specially crafted `email` parameter containing SQL injection payloads.
4.  The application fails to properly sanitize the `email` input, passing it directly to an SQL query.
5.  The injected SQL code is executed against the application's database.
6.  The attacker retrieves sensitive data, such as usernames, passwords, or other confidential information.
7.  The attacker may use the injected SQL to modify or delete data within the database.
8.  The attacker gains unauthorized administrative access to the Feedback System.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-8098) in code-projects Feedback System 1.0 can lead to the complete compromise of the affected system. An attacker could gain unauthorized access to sensitive data, modify or delete information, and potentially take control of the entire server. This could result in significant data breaches, financial losses, and reputational damage for organizations using the vulnerable software. Given the availability of a public exploit, the risk of widespread exploitation is elevated.

## Recommendation

*   Deploy the Sigma rule `Detect CVE-2026-8098 Exploitation — SQL Injection in code-projects Feedback System` to your SIEM to identify exploitation attempts targeting the vulnerable endpoint `/admin/checklogin.php`.
*   Apply input validation and sanitization to the `email` parameter in `/admin/checklogin.php` to prevent SQL injection, addressing the root cause of CVE-2026-8098.
*   Monitor web server logs for suspicious POST requests to `/admin/checklogin.php` containing SQL keywords or syntax in the `email` parameter.
*   Upgrade to a patched version of code-projects Feedback System that addresses this SQL injection vulnerability as soon as it becomes available.
