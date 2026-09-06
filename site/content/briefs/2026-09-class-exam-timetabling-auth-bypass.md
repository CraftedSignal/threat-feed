---
title: Authorization Bypass in SourceCodester Class and Exam Timetabling System
slug: 2026-09-class-exam-timetabling-auth-bypass
description: SourceCodester Class and Exam Timetabling System version 1.0 is vulnerable to a remote authorization bypass via the ID argument in /admin/session.php, enabling unauthenticated access to administrative functions.
date: "2026-09-04T11:25:24Z"
lastmod: "2026-09-06T18:47:14Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sourcecodester:class_and_exam_timetabling_system:1.0:*:*:*:*:*:*:*
tags:
  - sql-injection
  - vulnerability
  - web-application
vendors:
  - SourceCodester
products:
  - Class and Exam Timetabling System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument ID results in missing authorization. The attack can be executed remotely.
    confidence_band: high
cves:
  - id: CVE-2026-85512
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85512
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86220
rules:
  - title: Detect CVE-2026-85512 Exploitation - Authorization Bypass in /admin/session.php
    description: Detects exploitation attempts against CVE-2026-85512 by identifying requests to /admin/session.php with anomalous ID argument manipulation patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-86220 Exploitation - SQL Injection in Class and Exam Timetabling System
    description: Detects potential SQL injection attempts targeting the 'course' parameter in the modal_add_course.php script.
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
    - IT Operations
  immediate_actions:
    - action: Restrict access to /admin/session.php via WAF or web server configuration
      owner: IT Operations
      due: 24h
      evidence: Source notes remote exploitation capability
  mitigation_plan:
    - priority: immediate
      action: Disable access to the vulnerable system if no patch is available
      owner: IT Operations
      addresses: CVE-2026-85512
      evidence: Public exploit code availability
updates:
  - at: "2026-09-06T18:47:14Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-86220 Exploitation - SQL Injection in Class and Exam Timetabling System'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-86220
---

SourceCodester Class and Exam Timetabling System version 1.0 contains a critical missing authorization vulnerability identified as CVE-2026-85512. The flaw resides within the /admin/session.php file, where the ID argument is insufficiently validated. This vulnerability allows remote, unauthenticated attackers to bypass access controls and perform actions intended for administrative users. With exploit code currently available in the public domain, this vulnerability poses a significant risk to any organization deploying this specific version of the system. Defenders should prioritize identifying instances of this software within their environments and restricting access to administrative endpoints while awaiting a vendor patch or remediation.

## Impact

Successful exploitation allows unauthenticated remote attackers to bypass authorization, potentially leading to unauthorized data access, system configuration changes, or full administrative compromise of the affected Class and Exam Timetabling System instance.

## Recommendation

- Audit network assets to identify instances of SourceCodester Class and Exam Timetabling System version 1.0.
- Restrict access to the /admin/ directory and session.php files to trusted administrative IP addresses via firewall rules.
- Monitor web server access logs for anomalous GET or POST requests targeting /admin/session.php containing manipulated ID parameters.
