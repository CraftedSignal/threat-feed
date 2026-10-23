---
brief_id: brief-2026-10-23-siyuan-parser-differential
event_id: brief-2026-10-23-siyuan-parser-differential
revision: 1
activity_at: "2026-10-23T21:48:55Z"
title: 'SiYuan Kernel: Unauthenticated event stream access via URI parser differential (CVE-2026-73054)'
slug: 2026-10-siyuan-parser-differential
description: A parser differential in the SiYuan kernel WebSocket implementation allows unauthenticated attackers to bypass authentication by using duplicated query parameters, granting unauthorized access to the live event stream.
date: "2026-10-23T21:48:55Z"
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
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Verified against GHSA-c8w8-3pqp-wr83.
cpes:
  - cpe:2.3:a:siyuan_project:siyuan:*:*:*:*:*:*:*:*
tags:
  - web-application
  - websocket
  - rce-precursor
  - information-disclosure
vendors:
  - SiYuan
products:
  - SiYuan kernel (< 0.0.0-20260731131820-67bc300b6ea6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote caller obtains the kernel's live event stream on a deployment protected by an access auth code, with no user interaction and no prior knowledge of the instance.
    confidence_band: high
cves:
  - id: CVE-2026-73054
    cvss: 7.5
    epss: 0.00539
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-c8w8-3pqp-wr83
rules:
  - title: Detect CVE-2026-73054 Exploitation - WebSocket URI Parameter Duplication
    description: Detects exploitation attempts against SiYuan by identifying WebSocket requests to /ws containing duplicated 'id' or 'type' query parameters, a hallmark of the parser differential bypass.
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
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade SiYuan kernel to version 0.0.0-20260731131820-67bc300b6ea6 or later.
      owner: IT Operations
      due: 24h
      evidence: Source explicitly names the fixed version for this CVE.
  hunt_leads:
    - lead: Search web logs for WebSocket upgrade requests containing multiple 'id' or 'type' parameters.
      technique_id: T1190
      data_needed:
        - webserver access logs containing full query strings
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: POC demonstrates the use of duplicated query parameters to bypass quarantine.
  mitigation_plan:
    - priority: immediate
      action: Upgrade SiYuan kernel to 0.0.0-20260731131820-67bc300b6ea6
      owner: IT Operations
      addresses: CVE-2026-73054
      evidence: Remediation provided in GHSA advisory.
---

The SiYuan kernel suffers from a parser differential vulnerability where the logic used to exempt WebSocket keepalive sessions from authentication matches raw substrings, while the logic used to quarantine those sessions parses the query string. By sending a crafted URI containing duplicated 'id' and 'type' keys, an attacker can satisfy the authentication exemption while tricking the quarantine logic, leading to the session being placed in the active broadcast pool rather than a quarantined state. This issue, tracked as CVE-2026-73054, allows unauthenticated remote callers to receive live event streams on instances configured with an access auth code.

## Impact
Successful exploitation allows unauthenticated remote attackers to gain visibility into system metadata. Observed disclosed information includes document identifiers, document titles, notebook names, file paths, notebook child structures, and a real-time stream of create, update, and delete operations. Document body content is not currently confirmed to be exposed via this vector. The vulnerability also lacks origin validation, maintaining susceptibility to cross-origin attacks.

## Recommendation
- Upgrade the SiYuan kernel to version 0.0.0-20260731131820-67bc300b6ea6 or later immediately.
- Implement request-level monitoring on the `/ws` WebSocket endpoint to identify and block requests containing duplicate query parameters.
- Audit logs for WebSocket connections that establish session IDs associated with the broadcast pool while lacking valid session authentication tokens.
