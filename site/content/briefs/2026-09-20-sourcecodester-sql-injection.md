---
brief_id: brief-2026-09-20-sourcecodester-sql-injection
event_id: brief-2026-09-20-sourcecodester-sql-injection
revision: 2
activity_at: "2026-09-20T12:21:04Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:ebd1a26f0bddf251ac8a0871c3a76a4880b8effcb24afeefb58139979db93398
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: SQL Injection in SourceCodester Drug Recommendation System
slug: 2026-09-20-sourcecodester-sql-injection
description: SourceCodester Drug Recommendation System 1.0 is vulnerable to remote SQL injection via the ID argument in /Admin/edit_symptom.php, allowing unauthenticated attackers to manipulate backend database queries.
date: "2026-09-20T12:21:04Z"
lastmod: "2026-09-20T14:21:29Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source corroborated via NVD
cpes:
  - cpe:2.3:a:sourcecodester:drug_recommendation_system:1.0:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - sqli
vendors:
  - SourceCodester
products:
  - Drug Recommendation System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack is possible to be carried out remotely.
    confidence_band: high
cves:
  - id: CVE-2026-93997
    cvss: 7.3
    kev_status: unknown
  - id: CVE-2026-94015
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93997
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94015
rules:
  - title: Detects CVE-2026-93997 Exploitation - SQL Injection in edit_symptom.php
    description: Detects exploitation attempts targeting the ID parameter of /Admin/edit_symptom.php using common SQL injection characters
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-94015 Exploitation - SQL Injection in Drug Recommendation System
    description: Detects HTTP requests to the vulnerable edit_user.php script containing common SQL injection patterns in the ID parameter
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
    - action: Deploy Sigma detection rule to web application firewalls or SIEM
      owner: Detection Engineering
      due: 24h
      evidence: Source confirms public availability of exploit
  mitigation_plan:
    - priority: immediate
      action: Restrict external access to the /Admin/ directory
      owner: IT Operations
      addresses: CVE-2026-93997
      evidence: Vulnerability allows remote, unauthenticated SQL injection
updates:
  - at: "2026-09-20T14:21:29Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-94015 Exploitation - SQL Injection in Drug Recommendation System'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-94015
---

A SQL injection vulnerability has been identified in SourceCodester Drug Recommendation System version 1.0. The vulnerability resides within the /Admin/edit_symptom.php script, specifically affecting the handling of the 'ID' argument. This flaw allows remote, unauthenticated attackers to inject arbitrary SQL commands into the backend database. Publicly available exploit code exists, increasing the risk of unauthorized data access, modification, or complete database compromise. Organizations utilizing this software should restrict access to the administrative interface and review all application logs for anomalous SQL patterns originating from the /Admin/ directory.

## Impact

Successful exploitation of this vulnerability permits remote attackers to execute arbitrary SQL queries against the application database. This can lead to the unauthorized disclosure of sensitive medical or system data, modification of existing records, or potentially administrative account takeover. Given the nature of the application as a drug recommendation system, the integrity of the data is critical.

## Recommendation

- Restrict access to the /Admin/ directory to known, authorized IP addresses via web server access control lists.
- Deploy the provided Sigma rule to detect anomalous characters in the 'ID' parameter of the edit_symptom.php endpoint.
- Audit database logs for unusual queries or UNION-based SQL injection patterns associated with the user account running the web application service.
- Prioritize migration away from legacy, unsupported SourceCodester systems if patching is unavailable.
