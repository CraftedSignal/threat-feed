---
brief_id: brief-2026-10-27-asterisk-dos
event_id: brief-2026-10-27-asterisk-dos
revision: 2
activity_at: "2026-11-03T15:44:35Z"
revision_history:
  - revision: 2
    at: "2026-11-03T15:44:35Z"
    checksum: sha256:a25f21057130edebf1b6dcb2c0191131963cfdd173001f7111fa0a7eb4db6390
    summary: added coverage for Asterisk
    changed_fields:
      - action_plan
      - lastmod
      - references
      - severity
      - tags
      - ttps
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0327
title: 'Asterisk: Remote authenticated Denial of Service vulnerability'
slug: 2026-10-asterisk-dos
description: A vulnerability in Asterisk allows a remote, authenticated attacker to perform a Denial of Service attack.
date: "2026-10-27T17:35:12Z"
lastmod: "2026-11-03T15:43:43Z"
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
tags:
  - vulnerability
  - asterisk
  - sangoma
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
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker can exploit several vulnerabilities in Asterisk to execute arbitrary code with root privileges.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4176
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4205
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0327
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Inventory all Asterisk server versions
      owner: IT Operations
      due: 24h
      evidence: Multiple vulnerabilities in Asterisk require version verification for patching
    - action: Inventory all Asterisk instances and restrict access to management interfaces.
      owner: IT Operations
      due: 24h
      evidence: Vulnerabilities allow arbitrary code execution with root privileges.
  hunt_leads:
    - lead: Monitor for child processes spawned by the Asterisk service user that are not associated with known telephony functions
      technique_id: T1203
      data_needed:
        - Endpoint process monitoring (e.g., Auditd, Sysmon for Linux)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Ability for an attacker to execute arbitrary code within the telephony application environment
    - lead: Monitor for suspicious processes spawned by Asterisk service account or unexpected root process execution.
      technique_id: T1059
      data_needed:
        - Process creation logs (EID 1 or equivalent)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Arbitrary code execution with root privileges.
  mitigation_plan:
    - priority: immediate
      action: Apply available patches from Sangoma for Asterisk once identified
      owner: IT Operations
      addresses: Asterisk
      evidence: Multiple security vulnerabilities reported
    - priority: immediate
      action: Apply vendor-supplied patches as soon as they become available.
      owner: IT Operations
      addresses: Asterisk vulnerabilities
      evidence: BSI advisory indicates multiple vulnerabilities.
updates:
  - at: "2026-10-29T19:48:34Z"
    level: L1
    summary: added coverage for Asterisk
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4205
  - at: "2026-11-03T15:43:43Z"
    level: L2
    summary: added coverage for Asterisk
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0327
---

A vulnerability exists in Asterisk that enables a remote, authenticated attacker to trigger a Denial of Service (DoS) condition.
