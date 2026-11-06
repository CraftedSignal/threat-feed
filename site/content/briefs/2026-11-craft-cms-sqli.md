---
brief_id: brief-2026-11-06-craft-cms-sqli
event_id: brief-2026-11-06-craft-cms-sqli
revision: 1
activity_at: "2026-11-06T17:23:34Z"
title: 'Craft CMS: Unauthenticated SQL injection (CVE-2026-123488)'
slug: 2026-11-craft-cms-sqli
description: Craft CMS versions 4.0.0 through 4.18.8 and 5.0.0 through 5.11.1 contain an unauthenticated SQL injection vulnerability via the element search endpoint that enables remote attackers to perform unauthorized database operations and escalate privileges.
date: "2026-11-06T17:23:34Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified
cpes:
  - cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*
tags:
  - web-application
  - sql-injection
  - cve-2026-123488
vendors:
  - Craft CMS
products:
  - Craft CMS (4.0.0 through 4.18.8)
  - Craft CMS (5.0.0 through 5.11.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote attackers can read and write the database, setting the admin flag or overwriting password hashes in the users table to gain administrator access.
    confidence_band: high
cves:
  - id: CVE-2026-123488
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123488
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade vulnerable Craft CMS instances to 4.18.9 or 5.11.2
      owner: IT Operations
      due: 48h
      evidence: Craft CMS 4.0.0 before 4.18.9 and 5.0.0 before 5.11.2 contains an unauthenticated SQL injection
  hunt_leads:
    - lead: Identify HTTP GET/POST requests targeting the element search endpoint containing SQL injection payloads in the attribute parameter.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The element search endpoint because the attribute parameter is concatenated into the query unsanitized
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Craft CMS 4.18.9 or 5.11.2
      owner: IT Operations
      addresses: CVE-2026-123488
      evidence: Fixed versions 4.18.9 and 5.11.2 remediate the injection flaw
---

Craft CMS versions 4.0.0 through 4.18.8 and 5.0.0 through 5.11.1 are vulnerable to an unauthenticated SQL injection flaw in the element search endpoint. The vulnerability exists due to improper sanitization of the 'attribute' parameter in combination with emulated PDO prepares, which permits stacked SQL queries.

## Impact

An attacker can perform unauthorized read and write operations on the database. This allows for full database compromise, including the ability to overwrite user password hashes or modify administrative flags within the users table to gain persistent administrator access.

## Recommendation

- Upgrade Craft CMS 4.x installations to version 4.18.9 or later.
- Upgrade Craft CMS 5.x installations to version 5.11.2 or later.
- Review web server access logs for anomalous requests to the element search endpoint containing non-standard characters typically used for SQL injection, such as semicolons, comment markers, or SQL keywords in the 'attribute' query parameter.
