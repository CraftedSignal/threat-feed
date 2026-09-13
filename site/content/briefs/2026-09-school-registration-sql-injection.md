---
title: SQL Injection in SourceCodester School Registration and Fee System
slug: 2026-09-school-registration-sql-injection
description: CVE-2026-90514 is a remote SQL injection vulnerability in the School Registration and Fee System 1.0 that allows unauthenticated attackers to execute arbitrary database queries via the Status parameter.
date: "2026-09-13T11:25:23Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sourcecodester:school_registration_and_fee_system:1.0:*:*:*:*:*:*:*
vendors:
  - SourceCodester
products:
  - School Registration and Fee System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to launch the attack remotely.
    confidence_band: high
cves:
  - id: CVE-2026-90514
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90514
rules:
  - title: Detects CVE-2026-90514 Exploitation - SQL Injection via save_stud.php
    description: Detects exploitation attempts against the School Registration and Fee System by identifying SQL injection patterns in the Status parameter of the save_stud.php script.
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
    - IT Operations
  immediate_actions:
    - action: Deploy the provided Sigma rule to identify potential exploitation attempts.
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-90514 disclosure status
  mitigation_plan:
    - priority: immediate
      action: Identify and isolate instances of the School Registration and Fee System 1.0 until patches are verified.
      owner: IT Operations
      addresses: CVE-2026-90514
      evidence: NVD vulnerability disclosure
---

A remote SQL injection vulnerability, tracked as CVE-2026-90514, has been identified in SourceCodester School Registration and Fee System version 1.0. The flaw resides in the /bilal/normal/save_stud.php script, where the 'Status' argument is improperly sanitized before being processed by the application's database backend. 

This vulnerability allows a remote, unauthenticated attacker to manipulate SQL queries, which can lead to unauthorized data exfiltration, modification, or complete database compromise. Because this application is commonly deployed in school environments for managing student registration and fee collection, the potential impact includes the theft of sensitive personal identifiable information (PII) of students and faculty. Exploitation details have been disclosed publicly, increasing the likelihood of opportunistic attacks targeting exposed instances of this software. Defenders should prioritize patching or restricting access to the affected web application.

## Impact

The vulnerability poses a high risk to educational institutions utilizing the School Registration and Fee System 1.0. Successful exploitation allows for full unauthorized access to the underlying database, potentially resulting in the compromise of student financial records, personal identification, and administrative data. If exploited, attackers can exfiltrate sensitive records or delete database contents to disrupt system operations.

## Recommendation

- Perform a search for internet-facing instances of SourceCodester School Registration and Fee System and implement WAF rules to block requests containing SQL syntax in the Status parameter of /bilal/normal/save_stud.php.
- Review web server access logs for anomalous POST or GET requests to /bilal/normal/save_stud.php containing SQL keywords like UNION, SELECT, or SLEEP.
- If the application is not business-critical or can be replaced, decommission the instance until a vendor-provided security patch is applied.
