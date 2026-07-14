---
title: FacturaScripts Authenticated SQL Injection via Parenthesis Bypass
slug: 2026-07-facturascripts-sql-injection
description: An authenticated SQL injection vulnerability exists in the FacturaScripts REST API, specifically in the `filter` parameter of endpoints like `/api/3/clientes` and `/api/3/attachedfiles`. This flaw arises because the `Where::sqlColumn()` function bypasses identifier escaping for strings containing both parentheses, allowing an attacker to inject arbitrary SQL, which enables an attacker with a low-privileged API key to extract sensitive data like admin password hashes and session cookies (`logkey`) from any database table, leading to full account takeover and administrative access.
date: "2026-07-14T19:17:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - web-application
  - facturascripts
  - account-takeover
  - credential-access
  - privilege-escalation
vendors:
  - FacturaScripts
products:
  - FacturaScripts
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The attacker sends a crafted GET request with a malicious SQL injection payload in the `filter` parameter that allows arbitrary SQL to be executed, such as `UNION SELECT` or `SLEEP(2)`.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: The injected SQL query extracts sensitive data like the admin user's bcrypt password hash and `logkey` from the `users` table.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The attacker uses the leaked `logkey` to forge a session cookie and access administrative interfaces, achieving full account takeover.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An attacker with a low-privileged API key is able to gain full administrative control of the FacturaScripts application by leveraging stolen administrator credentials.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-5qmh-x653-g8qj
iocs:
  - type: value
    value: $2y$12$sLfA/XCqnjqLmYJwK.2V7eUHrHTHcQfkTYYfs1.lxX3OHrsmmkMGO
  - type: value
    value: HyZJB2eEyo5eC9Eyhn96qxbQkFDqHJss1d1lED0HEHE2ujoPPGRnUstsWd3kS25CieoLkHvsN4X1YGUt1iqXh1ZFMP0jgHFmeBW
ioc_counts:
  value: 2
rules:
  - title: Detect FacturaScripts Authenticated SQL Injection Attempt
    description: Detects authenticated SQL injection attempts targeting FacturaScripts REST API `filter` parameter by looking for parenthesis-bypassing injection patterns (e.g., UNION SELECT or SLEEP) in webserver logs.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
      - execution
      - privilege_escalation
    techniques:
      - T1003
      - T1059.006
      - T1078
    data_sources:
      - webserver
rules_count: 1
---

A critical authenticated SQL injection vulnerability (GHSA-5qmh-x653-g8qj) has been discovered in FacturaScripts, a popular ERP/CRM system, specifically impacting its REST API endpoints such as `/api/3/clientes` and `/api/3/attachedfiles`. This flaw stems from an insecure design in the `Where::sqlColumn()` function which fails to escape SQL identifiers that contain both opening and closing parentheses, allowing an attacker to inject arbitrary SQL into the `filter` parameter of API requests. An attacker with a legitimate, even low-privileged, API key (e.g., read-only access to a single resource) can leverage this vulnerability to bypass intended access controls. The exploit was verified on 2026-04-30 against a stock FacturaScripts master instance, demonstrating the ability to leak sensitive information such as admin password hashes and session cookies (`logkey`), ultimately leading to full administrative account takeover without requiring CSRF protection or two-factor authentication bypasses. This vulnerability poses a significant risk to the confidentiality and integrity of FacturaScripts deployments.

## Attack Chain

1. **Initial Access with Low-Privilege API Key:** An attacker obtains a valid, low-privileged API key, for example, a token with `allowget=1` on the `clientes` resource and `fullaccess=0`, typically intended for integrations or limited data retrieval.
2. **Crafted SQL Injection Request:** The attacker sends a GET request to a vulnerable API endpoint, such as `/api/3/clientes`, including a maliciously crafted `filter` parameter. The payload within the `filter` parameter contains SQL injection syntax, specifically leveraging parentheses to bypass the `Where::sqlColumn()` escaping mechanism (e.g., `filter[(0)UNION SELECT ...]=`).
3. **Database Query Manipulation:** The FacturaScripts backend processes the request, and due to the `Where::sqlColumn()` bypass, the attacker's SQL payload is concatenated directly into the database query, allowing for arbitrary SQL execution.
4. **Information Leakage (Password Hash):** The injected SQL query (e.g., `UNION SELECT IFNULL(password,2),... FROM users WHERE(nick='admin')`) extracts sensitive data like the admin user's bcrypt password hash from the `users` table.
5. **Information Leakage (Session Cookie):** The attacker repeats the process with a modified SQL injection payload to extract the admin user's `logkey` (web session cookie value).
6. **Session Hijacking:** With the leaked `logkey`, the attacker creates a forged session cookie for the admin user.
7. **Account Takeover:** The attacker uses the forged session cookie to access administrative interfaces (e.g., `/AdminPlugins`) of the FacturaScripts application, achieving full administrative account takeover.
8. **Arbitrary Command Execution (Optional):** Time-based blind SQL injection techniques (e.g., `(SELECT(SLEEP(2)))`) can also be employed to confirm the vulnerability in scenarios where `UNION SELECT` isn't feasible due to column count mismatches.

## Impact

The successful exploitation of this vulnerability leads to a severe cross-resource confidentiality breach and complete account takeover. An attacker starting with only a read-only API key for a single resource can escalate privileges to full administrator access. This allows them to read any data from any database table, including user credentials (password hashes), API keys, and sensitive business information. The attacker gains the ability to hijack administrator web sessions, granting them unfettered control over the FacturaScripts instance, including the installation of plugins, modification of settings, and potential data exfiltration or manipulation. The attack bypasses existing serialization protections for sensitive fields and API key scoping, making it a critical threat to data security and system integrity.

## Recommendation

* Deploy the Sigma rule `Detect FacturaScripts Authenticated SQL Injection Attempt` to your webserver logs to identify attempts at this exploitation.
* Review webserver access logs for requests containing patterns like `filter%5B%28` combined with `UNION%20SELECT` or `SLEEP%28` in `cs-uri-query`.
* Patch FacturaScripts installations immediately to address GHSA-5qmh-x653-g8qj once a fix is available, prioritizing internet-facing instances.
* Implement stringent API key management, including regular rotation and least-privilege principles, though this vulnerability demonstrates how such controls can be bypassed.
* Monitor for unusual administrator logins or activities originating from new or unexpected IP addresses, especially after suspicious API requests.
