---
brief_id: brief-2026-10-26-maccms-auth-bypass
event_id: brief-2026-10-26-maccms-auth-bypass
revision: 1
activity_at: "2026-10-26T15:43:34Z"
title: 'MacCMS: Authentication bypass in password recovery (CVE-2026-116214)'
slug: 2026-10-maccms-auth-bypass
description: MacCMS v10 before 2026.1000.4054 contains an authentication bypass vulnerability in the password recovery function that allows unauthenticated attackers to hijack arbitrary user accounts.
date: "2026-10-26T15:43:34Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:maccms:maccms:10:*:*:*:*:*:*:*
vendors:
  - MacCMS
products:
  - MacCMS (v10 < 2026.1000.4054)
cves:
  - id: CVE-2026-116214
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116214
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch MacCMS to version 2026.1000.4054 or later
      owner: IT Operations
      due: 24h
      evidence: MacCMS v10 before 2026.1000.4054 contains an authentication bypass vulnerability
  hunt_leads:
    - lead: Identify high volumes of password reset requests targeting multiple user identifiers from a single source IP
      technique_id: T1552.001
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can request a recovery code to their own mailbox via user/findpass_msg, then submit it to user/findpass_reset with the victim email or phone
  mitigation_plan:
    - priority: immediate
      action: Upgrade MacCMS v10 to 2026.1000.4054
      owner: IT Operations
      addresses: CVE-2026-116214
      evidence: MacCMS v10 before 2026.1000.4054 contains an authentication bypass vulnerability
---

MacCMS v10 versions prior to 2026.1000.4054 contain a critical vulnerability in the password reset process. The `check_msg()` function fails to validate the `msg_to` parameter during password recovery, enabling an attacker to bypass authentication. An attacker can initiate a password recovery request for a target account, intercept the recovery code sent to their own controlled address, and submit that code to the `user/findpass_reset` endpoint with the victim's email or phone number to change the password and gain unauthorized access.

## Impact

Successful exploitation allows unauthenticated attackers to gain full control over any member account, potentially leading to unauthorized data access or administrative account compromise.

## Recommendation

* Patch MacCMS v10 to version 2026.1000.4054 or later immediately.
* Audit web server logs for suspicious spikes in requests to `user/findpass_msg` and `user/findpass_reset` from single source IPs, which may indicate automated account takeover attempts.
