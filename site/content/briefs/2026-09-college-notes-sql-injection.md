---
title: SQL Injection in SourceCodester College Notes Gallery Management System
slug: 2026-09-college-notes-sql-injection
description: SourceCodester College Notes Gallery Management System version 1.0 contains a SQL injection vulnerability in the login.php file, allowing unauthenticated remote attackers to execute arbitrary database queries.
date: "2026-09-15T03:38:06Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sourcecodester:college_notes_gallery_management_system:*:*:*:*:*:*:*:*
tags:
  - sqli
  - vulnerability
  - web-application
vendors:
  - SourceCodester
products:
  - College Notes Gallery Management System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument User leads to sql injection.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-90849
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90849
rules:
  - title: Detect CVE-2026-90849 Exploitation - SQL Injection via Login
    description: Detects exploitation of CVE-2026-90849 by identifying SQL injection characters in the 'User' argument within POST requests to login.php
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review logs for indicators of SQL injection directed at /College/login.php
      owner: SOC
      due: 24h
      evidence: CVE-2026-90849 SQL injection report
  mitigation_plan:
    - priority: immediate
      action: Implement WAF blocking rules for SQLi signatures on the /College/login.php endpoint
      owner: IT Operations
      addresses: CVE-2026-90849
      evidence: NVD vulnerability details
---

SourceCodester College Notes Gallery Management System version 1.0 contains a critical SQL injection vulnerability in the login.php file. The application fails to properly sanitize the 'User' argument passed to the authentication endpoint. An unauthenticated remote attacker can exploit this flaw by submitting crafted input through the login form, allowing them to manipulate back-end database queries. This vulnerability is publicly disclosed, increasing the risk of exploitation by automated scanners and opportunistic threat actors. Successful exploitation can lead to unauthorized access, data exfiltration, or modification of the application database. Organizations using this software should restrict access to the login portal and prioritize remediation.

## Attack Chain

1. Attacker identifies the target login page hosted at /College/login.php.
2. Attacker probes the 'User' POST parameter for SQL injection vectors.
3. Attacker submits a crafted payload containing SQL special characters or logic-altering commands (e.g., OR 1=1).
4. The back-end database executes the injected command as part of the authentication check.
5. The application returns database information, bypasses authentication, or allows data manipulation.
6. Attacker gains unauthorized administrative access to the management system.

## Impact

Successful exploitation allows unauthenticated remote attackers to bypass authentication, potentially exposing sensitive college administrative data or gallery content. The impact includes full compromise of the application's database, leading to potential data loss or unauthorized administrative access to the platform.

## Recommendation

1. Restrict access to the /College/login.php endpoint to authorized IP ranges or implement WAF rules to detect and block SQL injection patterns.
2. Implement parameterized queries for all database interactions involving user-supplied input in the College Notes Gallery Management System.
3. Deploy the Sigma rules below to monitor for suspicious POST requests to the authentication endpoint containing SQL control characters.
4. Perform an audit of application database logs to identify signs of unauthorized access or unexpected error patterns.
