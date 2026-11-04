---
brief_id: brief-2026-11-04-rosariosis-sql-injection
event_id: brief-2026-11-04-rosariosis-sql-injection
revision: 1
activity_at: "2026-11-04T00:24:25Z"
title: 'RosarioSIS: SQL injection in StudentSummary.php (CVE-2026-121731)'
slug: 2026-11-rosariosis-sql-injection
description: Authenticated non-student users can exploit an unquoted SQL injection vulnerability in RosarioSIS versions prior to 12.9 to extract sensitive data or modify records.
date: "2026-11-04T00:24:25Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Content validated against NVD
cpes:
  - cpe:2.3:a:rosariosis:rosariosis:*:*:*:*:*:*:*:*
vendors:
  - RosarioSIS
products:
  - RosarioSIS (< 12.9)
cves:
  - id: CVE-2026-121731
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121731
rules:
  - title: Detect CVE-2026-121731 Exploitation - SQL Injection in StudentSummary.php
    description: Detects attempts to exploit the SQL injection vulnerability in StudentSummary.php by monitoring for suspicious SQL keywords or syntax in the period_id parameter.
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
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade RosarioSIS to 12.9
      owner: IT Operations
      due: 48h
      evidence: Source advises version 12.9 contains the fix
  hunt_leads:
    - lead: Identify authenticated sessions making repetitive or high-latency requests to StudentSummary.php
      technique_id: T1190
      data_needed:
        - Web access logs (cs-uri-stem, cs-uri-query, request duration)
        - Database slow query logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Source notes time-based SQL injection is a vector
  mitigation_plan:
    - priority: immediate
      action: Upgrade to RosarioSIS 12.9
      owner: IT Operations
      addresses: CVE-2026-121731
      evidence: Source indicates fix in 12.9
---

RosarioSIS versions before 12.9 contain a SQL injection vulnerability in the StudentSummary.php script. The vulnerability exists within the unquoted 'period_id' parameter, allowing authenticated non-student users, such as parents, to inject SQL payloads. Exploitation can lead to the exfiltration of sensitive information, including administrator password hashes and student records, via time-based queries or data modification through stacked statements.

## Impact

Successful exploitation allows authenticated users to bypass intended access controls to read or modify database content, including sensitive student data and administrator credentials.

## Recommendation

- Upgrade to RosarioSIS 12.9 or later to remediate the vulnerable parameter handling in StudentSummary.php.
- Review web access logs for requests to 'StudentSummary.php' containing abnormal characters or SQL keywords in the 'period_id' parameter.
- Audit database logs for unusual SQL syntax or time-based delay commands originating from authenticated user accounts.
