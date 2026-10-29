---
brief_id: brief-2026-10-27-asterisk-dos
event_id: brief-2026-10-27-asterisk-dos
revision: 1
activity_at: "2026-10-27T17:35:12Z"
title: 'Asterisk: Remote authenticated Denial of Service vulnerability'
slug: 2026-10-asterisk-dos
description: A vulnerability in Asterisk allows a remote, authenticated attacker to perform a Denial of Service attack.
date: "2026-10-27T17:35:12Z"
lastmod: "2026-10-29T19:48:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
vendors:
  - Sangoma
products:
  - Asterisk
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Ein entfernter, authentisierter Angreifer kann eine Schwachstelle in Asterisk ausnutzen, um einen Denial of Service Angriff durchzuführen.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Ein entfernter, anonymer Angreifer kann mehrere Schwachstellen in Asterisk ausnutzen, um einen Denial-of-Service-Angriff durchzuführen, beliebigen Programmcode auszuführen
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: oder seine Privilegien zu erhöhen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4176
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4205
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all Asterisk server versions
      owner: IT Operations
      due: 24h
      evidence: Multiple vulnerabilities in Asterisk require version verification for patching
  hunt_leads:
    - lead: Monitor for child processes spawned by the Asterisk service user that are not associated with known telephony functions
      technique_id: T1203
      data_needed:
        - Endpoint process monitoring (e.g., Auditd, Sysmon for Linux)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Ability for an attacker to execute arbitrary code within the telephony application environment
  mitigation_plan:
    - priority: immediate
      action: Apply available patches from Sangoma for Asterisk once identified
      owner: IT Operations
      addresses: Asterisk
      evidence: Multiple security vulnerabilities reported
updates:
  - at: "2026-10-29T19:48:34Z"
    level: L1
    summary: added coverage for Asterisk
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4205
---

A vulnerability exists in Asterisk that enables a remote, authenticated attacker to trigger a Denial of Service (DoS) condition.
