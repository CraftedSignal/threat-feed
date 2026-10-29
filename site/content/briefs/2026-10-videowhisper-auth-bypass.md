---
brief_id: brief-2026-10-29-videowhisper-auth-bypass
event_id: brief-2026-10-29-videowhisper-auth-bypass
revision: 1
activity_at: "2026-10-29T13:20:39Z"
title: 'VideoWhisper Broadcast Live Video: Missing Authorization Vulnerability (CVE-2026-115963)'
slug: 2026-10-videowhisper-auth-bypass
description: The VideoWhisper Broadcast Live Video WordPress plugin contains a missing authorization vulnerability (CVE-2026-115963) in versions up to 7.3.9, allowing unauthorized users to bypass access control checks.
date: "2026-10-29T13:20:39Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:videowhisper:broadcast_live_video:*:*:*:*:*:wordpress:*:*
tags:
  - vulnerability
  - wordpress
  - auth-bypass
vendors:
  - VideoWhisper
products:
  - Broadcast Live Video (<= 7.3.9)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Missing Authorization vulnerability in VideoWhisper.com Broadcast Live Video videowhisper-live-streaming-integration allows Exploiting Incorrectly Configured Access Control Security Levels.
    confidence_band: high
cves:
  - id: CVE-2026-115963
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115963
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory WordPress environments for Broadcast Live Video plugin versions <= 7.3.9
      owner: IT Operations
      due: 24h
      evidence: 'Vulnerability affects Broadcast Live Video: from n/a through 7.3.9.'
  hunt_leads:
    - lead: Monitor web server access logs for anomalous POST/GET requests directed at plugin-specific API endpoints or configuration pages
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Missing Authorization vulnerability ... allows Exploiting Incorrectly Configured Access Control Security Levels.
  mitigation_plan:
    - priority: immediate
      action: Disable the VideoWhisper Broadcast Live Video plugin until a patched version is released
      owner: IT Operations
      addresses: CVE-2026-115963
      evidence: 'The issue affects Broadcast Live Video: from n/a through 7.3.9.'
---

A missing authorization vulnerability in the VideoWhisper Broadcast Live Video WordPress plugin, tracked as CVE-2026-115963, allows unauthorized actors to perform actions restricted by access control levels. The vulnerability affects all versions up to and including 7.3.9. There is no information provided regarding a fix or update version at this time.

## Impact
Successful exploitation may allow an unauthorized user to perform administrative or restricted actions within the plugin, potentially leading to unauthorized access to features or data managed by the integration.

## Recommendation
- Inventory all WordPress instances running the VideoWhisper Broadcast Live Video plugin.
- Disable the plugin if it is not business-critical until an official security update is released by the vendor.
- Monitor WordPress administrative logs for unauthorized access to plugin settings or video stream configurations.
