---
title: SQL Injection Vulnerability in Drug Recommendation System
slug: 2026-10-drug-recommendation-sqli
description: The Drug Recommendation System 1.0 contains a SQL injection vulnerability in the 'cmdschool' parameter of the student registration module, allowing unauthenticated remote attackers to execute arbitrary database queries.
date: "2026-10-05T01:43:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:sourcecodester:drug_recommendation_system:1.0:*:*:*:*:*:*:*
tags:
  - sql-injection
  - web-vulnerability
vendors:
  - SourceCodester
products:
  - Drug Recommendation System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be executed remotely.
    confidence_band: high
cves:
  - id: CVE-2026-105175
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105175
rules:
  - title: Detects CVE-2026-105175 Exploitation - SQL Injection in Drug Recommendation System
    description: Detects attempts to exploit CVE-2026-105175 by monitoring POST/GET requests to add_student.php containing SQL injection characters in the cmdschool parameter.
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
    - action: Deploy Sigma rule to webserver logs to monitor for exploitation attempts targeting CVE-2026-105175.
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-105175
  mitigation_plan:
    - priority: immediate
      action: Implement WAF or input validation filter to sanitize the 'cmdschool' parameter in /Auth/add_student.php.
      owner: IT Operations
      addresses: CVE-2026-105175
      evidence: SQL injection vulnerability identified in component.
---

SourceCodester Drug Recommendation System version 1.0 contains a critical SQL injection vulnerability identified as CVE-2026-105175. The flaw resides within the /Auth/add_student.php script, specifically in the processing of the 'cmdschool' parameter within the Student Registration component. Because this parameter is inadequately sanitized before being processed by the backend database, an unauthenticated remote attacker can inject arbitrary SQL commands. Publicly available exploit material exists for this vulnerability, posing a significant risk to organizations using this software. Successful exploitation allows an attacker to manipulate database queries, potentially leading to unauthorized data access, modification, or deletion, depending on the privileges of the database service account.

## Impact

The vulnerability allows unauthenticated remote attackers to compromise the backend database associated with the Drug Recommendation System. This could lead to full data exfiltration of sensitive student or system records, integrity loss through unauthorized modifications, or complete database control, which may facilitate further system compromise.

## Recommendation

- Block requests targeting /Auth/add_student.php where the 'cmdschool' parameter contains common SQL injection sequences (e.g., apostrophes, comment characters).
- Deploy the provided Sigma rule to webserver logs to monitor for exploitation attempts targeting CVE-2026-105175.
- Audit database permissions for the web application service account to ensure the principle of least privilege is applied, limiting the impact of a successful SQL injection.
