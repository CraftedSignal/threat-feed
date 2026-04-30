---
title: WeGIA Web Manager SQL Injection Vulnerability (CVE-2026-35395)
slug: 2026-04-wegia-sql-injection
description: WeGIA web manager versions prior to 3.6.9 are vulnerable to SQL injection, allowing authenticated users to execute arbitrary SQL commands by directly interpolating the id_memorando parameter from $_REQUEST into SQL queries without validation, as identified by CVE-2026-35395.
date: "2026-04-06T21:16:21Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-35395
  - sql-injection
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-35395
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35395
  - https://github.com/LabRedesCefetRJ/WeGIA/security/advisories/GHSA-43jm-pcrq-w7gv
rules:
  - title: Detect Suspicious WeGIA SQL Injection Attempts
    description: Detects potential SQL injection attempts in WeGIA web application by monitoring for suspicious characters and keywords in the id_memorando parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WeGIA DespachoDAO.php Access with Potential SQL Injection
    description: Detects access to DespachoDAO.php with potentially malicious SQL injection attempts.
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

WeGIA (Web gerenciador para instituições assistenciais) is a web manager for charitable institutions. Versions prior to 3.6.9 are susceptible to a critical SQL injection vulnerability (CVE-2026-35395) found in the `dao/memorando/DespachoDAO.php` file. The `id_memorando` parameter, extracted from the `$_REQUEST` array, is directly incorporated into SQL queries without any validation or sanitization. This flaw enables authenticated users with low privileges to inject arbitrary SQL commands, potentially leading to complete database compromise. Successful exploitation could result in data breaches, modification of sensitive information, and denial-of-service conditions. Defenders should prioritize upgrading to version 3.6.9 or applying provided patches immediately.

## Attack Chain

1. An authenticated user logs into the WeGIA web application.
2. The user navigates to a page that triggers the execution of `dao/memorando/DespachoDAO.php`.
3. The application extracts the `id_memorando` parameter from the `$_REQUEST` array using the HTTP GET or POST method.
4. The attacker crafts a malicious `id_memorando` parameter containing SQL injection payloads (e.g., `1; DROP TABLE users; --`).
5. The application directly interpolates the attacker-controlled `id_memorando` parameter into an SQL query without proper sanitization within the `DespachoDAO.php` file.
6. The database server executes the injected SQL command, allowing the attacker to manipulate database records, read sensitive data, or execute arbitrary commands.
7. The attacker may exfiltrate sensitive data from the database, such as user credentials, financial information, or confidential memorandums.
8. The attacker achieves complete database compromise, potentially leading to a full system takeover.

## Impact

The SQL injection vulnerability in WeGIA versions prior to 3.6.9 poses a significant risk to charitable institutions using the software. Successful exploitation can lead to unauthorized access to sensitive donor information, financial records, and confidential communications. The potential impact includes data breaches, financial losses, reputational damage, and legal liabilities. Given the nature of the targeted institutions, this vulnerability could severely disrupt their operations and erode public trust, potentially affecting thousands of individuals. Organizations that do not apply the patch are vulnerable to data breaches.

## Recommendation

*   Immediately upgrade WeGIA to version 3.6.9 to remediate the SQL injection vulnerability described in CVE-2026-35395.
*   Implement input validation and sanitization for all user-supplied data, especially the `id_memorando` parameter in `DespachoDAO.php`, to prevent future SQL injection attacks.
*   Deploy the Sigma rule "Detect Suspicious WeGIA SQL Injection Attempts" to your SIEM and tune it for your environment to detect exploitation attempts.
*   Monitor web server logs for suspicious requests containing SQL injection payloads targeting the `dao/memorando/DespachoDAO.php` endpoint.
*   Restrict database access privileges to the minimum required for WeGIA to function correctly.
