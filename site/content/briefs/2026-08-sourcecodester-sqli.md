---
title: SQL Injection in SourceCodester Class and Exam Timetabling System
slug: 2026-08-sourcecodester-sqli
description: SourceCodester Class and Exam Timetabling System 1.0 contains an unauthenticated SQL injection vulnerability in edit_teacher.php that allows remote attackers to compromise database integrity.
date: "2026-08-15T18:20:05Z"
lastmod: "2026-08-18T00:51:50Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - web-application-vulnerability
  - sql-injection
  - cve-2026-75079
vendors:
  - SourceCodester
products:
  - Class and Exam Timetabling System
  - Class and Exam Timetabling System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be performed from remote.
    confidence_band: high
cves:
  - id: CVE-2026-19899
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75079
  - https://vuldb.com/vuln/391307
rules:
  - title: Detect CVE-2026-19899 Exploitation - SQL Injection in edit_teacher.php
    description: Detects exploitation attempts against the ID parameter in edit_teacher.php by looking for common SQL injection keywords and special characters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-75079 Exploitation - SQL Injection in edit_subject2.php
    description: Detects exploitation attempts against CVE-2026-75079 by monitoring for common SQL injection patterns in the ID parameter of edit_subject2.php requests
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
    - action: Deploy Sigma rule to detect exploitation attempts against edit_teacher.php
      owner: Detection Engineering
      due: 24h
      evidence: Source confirms public exploit disclosure.
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the application
      owner: IT Operations
      addresses: CVE-2026-19899
      evidence: SQL injection vulnerability allows remote unauthenticated access.
updates:
  - at: "2026-08-18T00:51:50Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-75079 Exploitation - SQL Injection in edit_subject2.php'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-75079
---

SourceCodester Class and Exam Timetabling System version 1.0 is affected by a critical SQL injection vulnerability. The flaw exists within the edit_teacher.php file, where the ID parameter fails to properly neutralize user-supplied input before using it in database queries. This vulnerability allows an unauthenticated, remote attacker to manipulate SQL commands, potentially leading to unauthorized data access, modification, or deletion within the underlying database. The vulnerability has been publicly disclosed with functional exploit code, increasing the risk of active exploitation. Organizations utilizing this software are at risk of complete database compromise if the application is exposed to the internet.

## Attack Chain

1. Attacker performs reconnaissance to identify instances of Class and Exam Timetabling System exposed to the internet.
2. Attacker probes the /edit_teacher.php endpoint to confirm the handling of the ID parameter.
3. Attacker crafts a malicious HTTP GET or POST request containing SQL injection payloads targeting the ID argument.
4. The application processes the request, passing the unvalidated input directly to the backend database query.
5. The database executes the injected SQL command, allowing the attacker to bypass authentication or extract sensitive records.
6. Attacker exfiltrates database contents or modifies administrative records to achieve further persistence or impact.

## Impact

Successful exploitation of this vulnerability results in unauthorized access to the application database. This can lead to the exposure of sensitive teacher, student, and scheduling information. Depending on database permissions, an attacker may be able to modify records, delete data, or potentially perform remote code execution if the database configuration allows for file system interactions or administrative command execution.

## Recommendation

1. Audit all web server logs for requests directed at /edit_teacher.php containing SQL-related metacharacters (e.g., single quotes, double dashes, OR 1=1).
2. Deploy the provided Sigma rule to detect attempts at exploiting this specific injection vector.
3. Restrict access to the application from untrusted networks and place it behind a Web Application Firewall (WAF) configured to inspect for SQL injection patterns.
4. If a patch is unavailable, consider deprecating the use of this software due to the lack of secure development practices indicated by this vulnerability.
