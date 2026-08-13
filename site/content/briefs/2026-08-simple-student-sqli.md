---
title: SQL Injection Vulnerability in SourceCodester Simple Student Information System
slug: 2026-08-simple-student-sqli
description: An unauthenticated remote SQL injection vulnerability in SourceCodester Simple Student Information System allows attackers to execute arbitrary database commands via the 'ID' parameter in 'view_department.php'.
date: "2026-08-13T16:56:42Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - web-application-attack
  - sql-injection
  - cve-2026-19710
vendors:
  - SourceCodester
products:
  - Simple Student Information System
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack is possible to be carried out remotely.
    confidence_band: high
cves:
  - id: CVE-2026-19710
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19710
  - https://vuldb.com/vuln/389368
rules:
  - title: Detects CVE-2026-19710 Exploitation - SQL Injection in view_department.php
    description: Detects attempts to exploit CVE-2026-19710 by identifying suspicious SQL keywords in the ID parameter of the view_department.php file.
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
    - action: Deploy the provided Sigma rule to detect exploitation attempts against CVE-2026-19710.
      owner: Detection Engineering
      due: 48h
      evidence: Exploit has been made public
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the /app/admin/ path.
      owner: IT Operations
      addresses: CVE-2026-19710
      evidence: Vulnerability exists in admin administrative file
---

The SourceCodester Simple Student Information System contains a critical SQL injection vulnerability identified as CVE-2026-19710. The vulnerability resides in the 'app/admin/departments/view_department.php' file, specifically within the handling of the 'ID' argument. An unauthenticated remote attacker can supply malicious SQL syntax through this parameter to interact directly with the underlying database. Publicly available exploit code exists, increasing the risk of active exploitation. This vulnerability allows for unauthorized data extraction, modification, or potential administrative access depending on the database configuration and application permissions. Defenders should monitor web logs for anomalous patterns in the 'ID' parameter targeting this specific file path.

## Attack Chain

1. Attacker performs reconnaissance to identify instances of Simple Student Information System running in the environment.
2. Attacker crafts a malicious HTTP GET or POST request targeting the 'app/admin/departments/view_department.php' endpoint.
3. Attacker injects SQL syntax into the 'ID' query parameter (e.g., 'ID=1 OR 1=1').
4. The vulnerable PHP script processes the unsanitized 'ID' input and includes it directly in a database query.
5. The backend database executes the injected SQL command.
6. The application returns database information, structure, or content in the HTTP response body.
7. Attacker extracts sensitive data from the database tables.

## Impact

Successful exploitation of CVE-2026-19710 enables an attacker to perform unauthorized database operations, leading to potential data exfiltration of student or administrative records, modification of application settings, or database-level persistence.

## Recommendation

1. Deploy a Web Application Firewall (WAF) rule to block requests containing common SQL injection characters (e.g., single quotes, union, select, sleep) in the 'ID' parameter directed at 'app/admin/departments/view_department.php'.
2. Implement the Sigma rule below to detect potential SQL injection attempts targeting the vulnerable endpoint in web server logs.
3. Validate if your organization uses Simple Student Information System and coordinate with IT teams to apply any available patches from the vendor or restrict external access to the administrative path.
