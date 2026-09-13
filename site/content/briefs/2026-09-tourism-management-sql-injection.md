---
title: SQL Injection Vulnerability in Tourism-Management-System
slug: 2026-09-tourism-management-sql-injection
description: The Tourism-Management-System contains a critical SQL injection vulnerability in the CommonDao component allowing remote unauthenticated attackers to execute arbitrary database queries.
date: "2026-09-07T08:51:39Z"
lastmod: "2026-09-13T13:26:01Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:jaychouchannel:tourism-management-system:*:*:*:*:*:*:*:*
tags:
  - web-application
  - sql-injection
  - cve-2026-86282
vendors:
  - jaychouchannel
products:
  - Tourism-Management-System (commits up to 8122bf020d91199eddfff3ee02d1632a70a9a132)
  - Tourism-Management-System (<= d984d172dceca907f8b447efbdb06dc233f7938d)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Executing a manipulation of the argument table/column/xColumn/yColumn can lead to sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-86282
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86282
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90522
rules:
  - title: Detects CVE-2026-86282 Exploitation - SQL Injection in CommonController
    description: Detects exploitation attempts against the Tourism-Management-System CommonController by identifying SQL injection payloads in the table or column parameters.
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
    - action: Deploy WAF rules to block SQL keywords in the specified parameters
      owner: SOC
      due: 24h
      evidence: Exploit relies on SQL injection in parameters
  mitigation_plan:
    - priority: immediate
      action: Apply patch d44ec3aa0bd2a72c8800e3befb0a9a96a6491b86
      owner: IT Operations
      addresses: CVE-2026-86282
      evidence: NVD vulnerability mitigation recommendation
updates:
  - at: "2026-09-13T13:26:01Z"
    level: L2
    summary: added coverage for Tourism-Management-System (<= d984d172dceca907f8b447efbdb06dc233f7938d)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-90522
---

A SQL injection vulnerability exists in the Tourism-Management-System repository maintained by jaychouchannel. The flaw resides within the CommonDao component, specifically inside the 'travel/src/main/java/com/controller/CommonController.java' file. An attacker can exploit this remotely by injecting malicious input into the 'table', 'column', 'xColumn', or 'yColumn' parameters. Because the application fails to properly sanitize these inputs before including them in SQL queries, an attacker can bypass authentication, exfiltrate sensitive data, or modify database contents. 

Publicly available exploit code has been released, increasing the risk of exploitation. As the project does not utilize standard versioning, all instances running commits up to 8122bf020d91199eddfff3ee02d1632a70a9a132 are considered vulnerable. Security teams should prioritize patching the system using the official fix provided in commit d44ec3aa0bd2a72c8800e3befb0a9a96a6491b86.

## Impact

Successful exploitation allows remote, unauthenticated attackers to perform SQL injection attacks. This can result in unauthorized access to sensitive application data, potential modification or deletion of records, and under certain configurations, escalation of privileges or administrative takeover of the backend database. All organizations hosting this system are at risk of data breaches and service disruption.

## Recommendation

* Apply the security patch provided in commit d44ec3aa0bd2a72c8800e3befb0a9a96a6491b86 to all instances of the Tourism-Management-System.
* Audit access logs for abnormal HTTP requests containing SQL keywords (e.g., SELECT, UNION, SLEEP) targeting the CommonController endpoint.
* Enforce strict input validation on all parameters handled by CommonController.java.
* Monitor webserver traffic for incoming requests where the query parameters 'table', 'column', 'xColumn', or 'yColumn' contain suspicious SQL syntax or metacharacters.
