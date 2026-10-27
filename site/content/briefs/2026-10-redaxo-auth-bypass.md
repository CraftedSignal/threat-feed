---
brief_id: brief-2026-10-27-redaxo-auth-bypass
event_id: brief-2026-10-27-redaxo-auth-bypass
revision: 1
activity_at: "2026-10-27T11:46:05Z"
title: 'REDAXO Core: Authentication bypass vulnerability (CVE-2026-117532)'
slug: 2026-10-redaxo-auth-bypass
description: REDAXO core versions 5.3.0 through 5.21.3 contain an authentication bypass vulnerability in the structure/history plugin that allows unauthenticated attackers to forge administrative login tokens and achieve code execution.
date: "2026-10-27T11:46:05Z"
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
  validation_status: verified against NVD metadata
cpes:
  - cpe:2.3:a:redaxo:redaxo:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication-bypass
  - webserver
vendors:
  - REDAXO
products:
  - REDAXO core (< 5.21.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows unauthenticated attackers to forge temporary login tokens, gaining backend access.
    confidence_band: high
cves:
  - id: CVE-2026-117532
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117532
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade REDAXO core to 5.21.4 or later
      owner: IT Operations
      due: 24h
      evidence: Source identifies vulnerability in versions < 5.21.4
  hunt_leads:
    - lead: Identify suspicious access attempts to structure/history plugin endpoints
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability exists specifically in the structure/history plugin
  mitigation_plan:
    - priority: immediate
      action: Upgrade REDAXO core to 5.21.4
      owner: IT Operations
      addresses: CVE-2026-117532
      evidence: NVD vulnerability details
---

REDAXO core from 5.3.0 before 5.21.4 contains an authentication bypass vulnerability in the structure/history plugin. The vulnerability allows unauthenticated attackers to manipulate the session-tied secret into a predictable state, facilitating the forgery of administrative login tokens. Successful exploitation grants attackers unauthorized backend access and the ability to achieve code execution.

## Impact

Successful exploitation results in full unauthorized backend access and subsequent code execution.

## Recommendation

* Upgrade to REDAXO version 5.21.4 or later immediately to patch CVE-2026-117532.
* Audit web server access logs for anomalous requests directed at the 'structure/history' plugin endpoint that result in successful logins.
* Monitor for unexpected administrative logins originating from unfamiliar IP addresses.
