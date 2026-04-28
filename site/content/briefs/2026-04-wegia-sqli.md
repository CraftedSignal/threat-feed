---
title: WeGIA SQL Injection Vulnerability (CVE-2026-40285)
slug: 2026-04-wegia-sqli
description: WeGIA versions prior to 3.6.10 are vulnerable to SQL injection via the cpf_usuario POST parameter, allowing authenticated users to query the database under an arbitrary identity.
date: "2026-04-18T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - wegia
  - sql-injection
  - cve-2026-40285
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40285
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40285
rules:
  - title: Detect WeGIA SQL Injection Attempt via cpf_usuario Parameter
    description: Detects potential SQL injection attempts in WeGIA by monitoring HTTP POST requests with suspicious payloads in the cpf_usuario parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect WeGIA SQL Injection Attempt via cpf_usuario Parameter - Error Based
    description: Detects potential SQL injection attempts in WeGIA by monitoring HTTP POST requests with error inducing payloads in the cpf_usuario parameter.
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

WeGIA, a web manager for charitable institutions, is susceptible to a SQL injection vulnerability affecting versions prior to 3.6.10. This flaw, identified as CVE-2026-40285, resides in the `dao/memorando/UsuarioDAO.php` file. The vulnerability stems from the insecure handling of the `cpf_usuario` POST parameter within the `DespachoControle::verificarDespacho()` function, where the `extract($_REQUEST)` function overwrites the session-stored user identity. An attacker can then manipulate the `cpf_usuario` value, which is subsequently interpolated directly into a raw SQL query. This allows an authenticated user to execute arbitrary SQL queries with the privileges of an arbitrary user, potentially gaining unauthorized access to sensitive data. WeGIA version 3.6.10 addresses and resolves this critical vulnerability.

## Attack Chain

1. An attacker authenticates to the WeGIA web application.
2. The attacker crafts a malicious HTTP POST request targeting the endpoint associated with `DespachoControle::verificarDespacho()`.
3. The crafted POST request includes the `cpf_usuario` parameter with a SQL injection payload.
4. The `extract($_REQUEST)` function processes the POST data, overwriting the legitimate session-stored user identity with the attacker-controlled `cpf_usuario` value.
5. The application constructs a raw SQL query, directly interpolating the malicious `cpf_usuario` value into the query string without proper sanitization.
6. The database executes the crafted SQL query, effectively querying the database as an arbitrary user specified by the attacker in the `cpf_usuario` parameter.
7. The application returns the results of the injected SQL query to the attacker, potentially revealing sensitive information.
8. The attacker can leverage the SQL injection to perform unauthorized data retrieval, modification, or deletion within the WeGIA application.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-40285) allows attackers to bypass authentication and access sensitive data within the WeGIA application. This could lead to the compromise of user accounts, financial records, or other confidential information managed by charitable institutions using WeGIA. The impact could range from data breaches and financial losses to reputational damage and legal repercussions for the affected organizations. The CVSS v3.1 base score of 8.8 indicates a high level of severity.

## Recommendation

*   Upgrade WeGIA installations to version 3.6.10 or later to remediate CVE-2026-40285.
*   Deploy the following Sigma rule to detect exploitation attempts by monitoring for POST requests containing potentially malicious SQL injection payloads in the `cpf_usuario` parameter.
*   Implement input validation and sanitization measures for all user-supplied data, especially within the `DespachoControle::verificarDespacho()` function to prevent future SQL injection vulnerabilities.
*   Review web server logs for suspicious POST requests targeting WeGIA endpoints to identify potential exploitation attempts.
