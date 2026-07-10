---
title: LORIS SQL Injection Vulnerability (CVE-2026-33350)
slug: 2024-01-loris-sql-injection
description: A SQL injection vulnerability exists in LORIS versions prior to 27.0.3 and 28.0.1, allowing attackers to access or alter data via the MRI feedback popup window in the imaging browser.
date: "2024-01-30T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2026-33350
  - loris
  - web-application
vendors:
  - LORIS
products:
  - LORIS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-33350
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33350
  - https://github.com/aces/Loris/security/advisories/GHSA-9r29-6jgc-3ggh
rules:
  - title: Detect Potential LORIS SQL Injection Attempts via URI
    description: Detects potential SQL injection attempts against LORIS by monitoring for suspicious SQL syntax within URI queries.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Potential LORIS SQL Injection Attempts via POST data
    description: Detects potential SQL injection attempts against LORIS by monitoring for suspicious SQL syntax within POST request data.
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

LORIS (Longitudinal Online Research and Imaging System) is a self-hosted web application used for data and project management in neuroimaging research. A SQL injection vulnerability, identified as CVE-2026-33350, affects versions prior to 27.0.3 and 28.0.1. The vulnerability is located in code sections related to the MRI feedback popup window within the imaging browser. An attacker exploiting this flaw could potentially gain unauthorized access to sensitive data or modify existing records stored on the server. Organizations utilizing vulnerable LORIS versions are at risk of data breaches and integrity compromises. Upgrading to version 27.0.3 or 28.0.1 is advised to mitigate this risk.

## Attack Chain

1.  An attacker identifies a LORIS instance running a vulnerable version (prior to 27.0.3 or 28.0.1).
2.  The attacker crafts a malicious SQL payload designed to exploit the injection point within the MRI feedback popup window of the imaging browser.
3.  The attacker injects the SQL payload through a user-supplied input field related to the MRI feedback feature.
4.  The LORIS application, without proper sanitization or input validation, executes the attacker-controlled SQL query against the database.
5.  Depending on the injected payload, the attacker can read sensitive data from the database, such as patient information or research data.
6.  Alternatively, the attacker could modify existing data, potentially corrupting research results or manipulating patient records.
7.  The attacker may attempt to escalate privileges within the database or gain access to the underlying operating system, depending on the database configuration and permissions.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-33350) could lead to unauthorized access to sensitive patient data and research information stored within the LORIS system. This could result in violations of privacy regulations (e.g., HIPAA), reputational damage for the affected organization, and potential legal liabilities. Data modification could compromise the integrity of research findings and impact clinical decision-making. While the number of affected installations is unknown, the self-hosted nature of LORIS means that each vulnerable instance is a potential target.

## Recommendation

*   Upgrade LORIS installations to version 27.0.3 or 28.0.1 to patch CVE-2026-33350 as recommended by the vendor.
*   Implement input validation and sanitization measures within the LORIS application to prevent SQL injection attacks.
*   Deploy the Sigma rule provided below to detect potential exploitation attempts against LORIS instances.
*   Review web server logs for suspicious activity targeting the MRI feedback functionality to identify potential exploitation attempts.
