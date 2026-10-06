---
title: SQL Injection in Simple Student Information System
slug: 2026-10-simple-student-sqli
description: SourceCodester Simple Student Information System version 1.0 is vulnerable to remote SQL injection in the searchquery.php file, allowing unauthenticated attackers to manipulate database queries.
date: "2026-10-06T08:54:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sourcecodester:simple_student_information_system:1.0:*:*:*:*:*:*:*
tags:
  - sqli
  - web-vulnerability
vendors:
  - SourceCodester
products:
  - Simple Student Information System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-105807
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105807
rules:
  - title: Detect CVE-2026-105807 Exploitation - SQL Injection in searchquery.php
    description: Detects potential SQL injection attempts against the vulnerable searchquery.php file
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
    - action: Deploy WAF rules to block SQL injection patterns targeting /searchquery.php
      owner: SOC
      due: 24h
      evidence: CVE-2026-105807 description
  mitigation_plan:
    - priority: immediate
      action: Restrict access to Simple Student Information System to trusted networks
      owner: IT Operations
      addresses: CVE-2026-105807
      evidence: Source advisory
---

SourceCodester Simple Student Information System version 1.0 contains a SQL injection vulnerability within the searchquery.php script. The application fails to properly sanitize user-supplied input before incorporating it into database queries, allowing remote, unauthenticated attackers to inject arbitrary SQL commands. This vulnerability can lead to unauthorized data exfiltration, modification, or potential administrative bypass depending on the database configuration and permissions associated with the application's service account. Because the vulnerability is exploitable remotely, it presents a significant risk to organizations hosting this software in internet-facing environments.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to the underlying database. Depending on the environment, this may lead to the exposure of sensitive student records, compromise of user authentication credentials, or full application takeover.

## Recommendation

Identify all instances of Simple Student Information System 1.0 in your environment. Since the vendor has not provided a patch as of the report date, implement strict input validation at the web application firewall (WAF) level to block SQL injection patterns targeting searchquery.php. Restrict access to the application to trusted internal networks until a remediation version is available.
