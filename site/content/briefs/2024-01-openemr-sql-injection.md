---
title: OpenEMR PostCalendar Blind SQL Injection Vulnerability (CVE-2026-33914)
slug: 2024-01-openemr-sql-injection
description: A blind SQL injection vulnerability exists in the PostCalendar module of OpenEMR versions prior to 8.0.0.3 due to improper sanitization of the `dels` POST parameter, potentially allowing attackers to execute arbitrary SQL commands.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openemr
  - sql-injection
  - cve-2026-33914
  - web-application
vendors:
  - OpenEMR
products:
  - OpenEMR
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33914
rules:
  - title: Detect OpenEMR PostCalendar SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the OpenEMR PostCalendar module by looking for suspicious characters and SQL keywords in the 'dels' POST parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1211
    data_sources:
      - webserver
      - linux
  - title: Detect OpenEMR SQL DELETE Statement Execution via Doctrine DBAL
    description: This rule detects the execution of SQL DELETE statements by Doctrine DBAL within OpenEMR, which may indicate a successful SQL injection.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenEMR, a widely used open-source electronic health records (EHR) and medical practice management application, is vulnerable to a blind SQL injection flaw (CVE-2026-33914) affecting versions prior to 8.0.0.3. The vulnerability resides within the PostCalendar module, specifically in the `categoriesUpdate` administrative function. The application fails to adequately sanitize the `dels` POST parameter, which is then directly incorporated into a raw SQL `DELETE` statement. This lack of sanitization allows a malicious actor to inject arbitrary SQL code, potentially leading to data breaches, system compromise, and unauthorized access to sensitive patient information. Organizations using vulnerable OpenEMR instances are at significant risk until they upgrade to version 8.0.0.3 or apply the necessary patches.

## Attack Chain

1.  Attacker identifies an OpenEMR instance running a version prior to 8.0.0.3.
2.  Attacker crafts a malicious HTTP POST request targeting the `/modules/PostCalendar/postcalendar.php` endpoint.
3.  The POST request includes the `dels` parameter containing a crafted SQL injection payload.
4.  OpenEMR's `pnVarCleanFromInput()` function strips HTML tags from the `dels` parameter, but does not perform SQL escaping.
5.  The unsanitized `dels` parameter is directly interpolated into a raw SQL `DELETE` statement.
6.  Doctrine DBAL's `executeStatement()` executes the malicious SQL query against the OpenEMR database.
7.  The attacker uses blind SQL injection techniques (e.g., time-based or boolean-based) to exfiltrate data or modify database records.
8.  Successful exploitation leads to unauthorized access to patient data, modification of records, or complete database compromise.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-33914) can lead to severe consequences for healthcare providers and their patients. Potential impacts include unauthorized access to and exfiltration of sensitive patient data (PHI), modification or deletion of critical medical records, disruption of clinical operations, and potential regulatory fines for HIPAA violations. The number of affected OpenEMR installations is substantial, making this a widespread threat.

## Recommendation

*   Immediately upgrade OpenEMR installations to version 8.0.0.3 to patch CVE-2026-33914.
*   Deploy the Sigma rule "Detect OpenEMR PostCalendar SQL Injection Attempt" to detect exploitation attempts targeting the vulnerable endpoint.
*   Monitor web server logs for suspicious POST requests to `/modules/PostCalendar/postcalendar.php` containing unusual characters or SQL keywords in the `dels` parameter to detect potential exploitation attempts.
