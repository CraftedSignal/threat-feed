---
brief_id: brief-2026-11-05-kobikom-sqli
event_id: brief-2026-11-05-kobikom-sqli
revision: 1
activity_at: "2026-11-05T14:41:01Z"
title: 'Kobikom KobiPBX: SQL injection vulnerability (CVE-2026-105321)'
slug: 2026-11-kobikom-sqli
description: An SQL injection vulnerability exists in Kobikom KobiPBX versions prior to r1, allowing attackers to inject arbitrary SQL commands into the backend database.
date: "2026-11-05T14:41:01Z"
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
  validation_status: Patching is the primary mitigation; no specific telemetry or exploit vector provided by NVD.
cpes:
  - cpe:2.3:a:kobikom:kobipbx:*:*:*:*:*:*:*:*
tags:
  - sqli
  - vulnerability
  - webserver
vendors:
  - Kobikom
products:
  - KobiPBX-FOP3-SEC (< r1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Improper neutralization of special elements used in an SQL command (SQL injection) vulnerability in Kobikom Telecommunications and Informatics Services Inc. Kobikom allows SQL Injection.
    confidence_band: high
cves:
  - id: CVE-2026-105321
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105321
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade KobiPBX-FOP3-SEC to r1 or later
      owner: IT Operations
      due: 48h
      evidence: 'Issue affects Kobikom: before KobiPBX-FOP3-SEC-r1.'
  hunt_leads:
    - lead: Monitor web access logs for common SQL injection patterns targeting KobiPBX management interfaces
      technique_id: T1505
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: SQL injection vulnerability in Kobikom Telecommunications and Informatics Services Inc. Kobikom allows SQL Injection.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to KobiPBX-FOP3-SEC-r1
      owner: IT Operations
      addresses: CVE-2026-105321
      evidence: 'This issue affects Kobikom: before KobiPBX-FOP3-SEC-r1.'
---

Kobikom Telecommunications and Informatics Services Inc. has disclosed an improper neutralization of special elements used in an SQL command (SQL injection) vulnerability within its KobiPBX product. The flaw exists in versions prior to KobiPBX-FOP3-SEC-r1. Exploitation could allow an attacker to perform unauthorized database actions, such as data retrieval or modification.

## Impact

Successful exploitation allows for unauthorized interaction with the backend database. While specific impact is not documented, SQL injection typically permits data exfiltration, database manipulation, or authentication bypass.

## Recommendation

- Inventory all instances of Kobikom KobiPBX within the network to identify versions below KobiPBX-FOP3-SEC-r1.
- Upgrade all affected KobiPBX installations to the secure release (KobiPBX-FOP3-SEC-r1) or newer immediately.
- Until patching is complete, restrict access to the web management interface of KobiPBX to authorized internal management networks only.
