---
title: FreePBX Security Advisories for Security-Reporting Module Vulnerabilities
slug: 2026-05-freepbx-vulns
description: FreePBX released security advisories addressing authenticated SQL injection and local file inclusion vulnerabilities in the Security-Reporting cdr and dashboard modules for FreePBX 16 and 17.
date: "2026-05-20T15:15:37Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - freepbx
  - sql_injection
  - lfi
  - vulnerability
vendors:
  - FreePBX
products:
  - Security-Reporting cdr (FreePBX 16)
  - Security-Reporting cdr (FreePBX 17)
  - Security-Reporting dashboard (FreePBX 16)
  - Security-Reporting dashboard (FreePBX 17)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://cyber.gc.ca/en/alerts-advisories/freepbx-security-advisory-av26-484
  - https://github.com/FreePBX/security-reporting/security/advisories/GHSA-p9fq-fmpw-2h9x
  - https://github.com/FreePBX/security-reporting/security/advisories/GHSA-hw7v-v2jp-wc4v
  - https://github.com/FreePBX/security-reporting/security/advisories?state=published
rules:
  - title: Detect Suspicious ORDER BY Clause in Web Requests (Potential SQL Injection)
    description: Detects suspicious ORDER BY clauses in web requests, potentially indicating SQL injection attempts (GHSA-p9fq-fmpw-2h9x).
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
  - title: Detect Local File Inclusion Attempt via Directory Traversal
    description: Detects attempts to exploit Local File Inclusion (LFI) vulnerabilities (GHSA-hw7v-v2jp-wc4v) through directory traversal sequences in web requests.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
rules_count: 2
---

On May 19, 2026, FreePBX published security advisories to address vulnerabilities affecting the Security-Reporting cdr and dashboard modules in FreePBX versions 16 and 17. These vulnerabilities include an authenticated SQL Injection vulnerability (GHSA-p9fq-fmpw-2h9x) in the CDR reports due to insufficient input sanitization in the ORDER BY clause and an authenticated Local File Inclusion (LFI) vulnerability (GHSA-hw7v-v2jp-wc4v) in the dashboard module. Successful exploitation of these vulnerabilities could allow an authenticated attacker to execute arbitrary SQL queries or read sensitive files on the server. FreePBX versions affected are Security-Reporting cdr (FreePBX 16) versions 16.0.50 and prior, Security-Reporting cdr (FreePBX 17) versions 17.0.11 and prior, Security-Reporting dashboard (FreePBX 16) versions 16.0.22 and prior, and Security-Reporting dashboard (FreePBX 17) versions 17.0.5 and prior.

## Attack Chain

1. An attacker authenticates to the FreePBX web interface using valid credentials.
2. For SQL Injection (GHSA-p9fq-fmpw-2h9x), the attacker navigates to the CDR Reports section of the Security-Reporting cdr module.
3. The attacker crafts a malicious SQL payload within the ORDER BY parameter of the CDR report request. This could involve injecting SQL code into the `sort` parameter.
4. The application executes the attacker-controlled SQL query against the FreePBX database.
5. The attacker extracts sensitive information from the database, potentially including user credentials or call records.
6. For Local File Inclusion (GHSA-hw7v-v2jp-wc4v), the attacker accesses the Dashboard module.
7. The attacker manipulates input parameters to include directory traversal sequences, such as "../", to access arbitrary files on the system.
8. The attacker retrieves sensitive files, such as configuration files or private keys, from the FreePBX server.

## Impact

Successful exploitation of these vulnerabilities can lead to unauthorized access to sensitive information, including database credentials, call records, and system files. An attacker could potentially use the SQL injection vulnerability to gain complete control over the FreePBX database, leading to data breaches or service disruption. The LFI vulnerability could expose sensitive configuration files or private keys, potentially allowing the attacker to compromise the entire system. The number of affected systems depends on the deployment size of vulnerable FreePBX installations.

## Recommendation

*   Apply the necessary updates provided by FreePBX to patch the SQL Injection (GHSA-p9fq-fmpw-2h9x) and Local File Inclusion (GHSA-hw7v-v2jp-wc4v) vulnerabilities in the Security-Reporting cdr and dashboard modules.
*   Monitor web server logs for suspicious requests containing SQL injection attempts or directory traversal sequences targeting the affected FreePBX modules.
*   Implement input validation and sanitization measures to prevent SQL injection and LFI vulnerabilities in web applications.
*   Deploy the Sigma rule for suspicious ORDER BY clauses in web requests to detect potential SQL injection attempts.
*   Review access controls to the FreePBX web interface and limit access to authorized personnel only.
