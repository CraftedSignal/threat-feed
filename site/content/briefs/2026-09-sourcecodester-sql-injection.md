---
title: SQL Injection in SourceCodester Online Reviewer Management System
slug: 2026-09-sourcecodester-sql-injection
description: SourceCodester Online Reviewer Management System 1.0 contains a SQL injection vulnerability in the questions-view.php script, allowing remote attackers to execute unauthorized database queries.
date: "2026-09-30T04:31:33Z"
lastmod: "2026-09-30T04:31:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sourcecodester:online_reviewer_management_system:1.0:*:*:*:*:*:*:*
tags:
  - sql-injection
  - web-application
  - cve-2026-102908
  - web-application-vulnerability
  - vulnerability-management
vendors:
  - SourceCodester
products:
  - Online Reviewer Management System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A vulnerability was determined in SourceCodester Online Reviewer Management System 1.0.
    confidence_band: high
cves:
  - id: CVE-2026-102908
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102908
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102910
rules:
  - title: Detect CVE-2026-102908 Exploitation - SQL Injection in questions-view.php
    description: Detects potential SQL injection attempts targeting the ID parameter in the vulnerable questions-view.php script.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-102910 Exploitation - SQL Injection in exam-delete.php
    description: Detects attempts to exploit CVE-2026-102910 by identifying SQL syntax injection patterns within the test_id argument on the exam-delete.php endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review web logs for access to /reviewer_0/admins/assessments/examproper/questions-view.php
      owner: SOC
      due: 24h
      evidence: Source reporting of CVE-2026-102908
  mitigation_plan:
    - priority: immediate
      action: Implement input sanitization for ID parameter in questions-view.php
      owner: IT Operations
      addresses: CVE-2026-102908
      evidence: SQL injection vulnerability in specific script
updates:
  - at: "2026-09-30T04:31:53Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-102910 Exploitation - SQL Injection in exam-delete.php'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-102910
---

A SQL injection vulnerability has been identified in SourceCodester Online Reviewer Management System version 1.0. The vulnerability resides within the file /reviewer_0/admins/assessments/examproper/questions-view.php. An attacker can perform remote exploitation by manipulating the ID parameter passed to this script. Successful exploitation allows for the execution of arbitrary SQL commands against the backend database, potentially leading to unauthorized data exfiltration, modification, or administrative access to the underlying management system. Given that the exploit has been publicly disclosed, organizations utilizing this software are at an elevated risk of automated or targeted exploitation attempts.

## Impact

Successful exploitation of CVE-2026-102908 permits an unauthenticated remote attacker to compromise the integrity and confidentiality of the application database. Potential impacts include the dumping of sensitive reviewer or exam information, modification of administrative credentials, or full takeover of the application instance.

## Recommendation

- Monitor web server access logs for anomalous GET or POST requests directed at /reviewer_0/admins/assessments/examproper/questions-view.php containing SQL syntax characters (e.g., apostrophes, double-dashes, keywords like UNION or SELECT).
- Apply input validation and parameterized queries to the ID parameter in the affected PHP script.
- Implement a Web Application Firewall (WAF) to block requests containing common SQL injection patterns targeting the identified endpoint.
