---
brief_id: brief-2026-10-26-maccms-auth-bypass
event_id: brief-2026-10-26-maccms-auth-bypass
revision: 2
activity_at: "2026-11-06T04:43:46Z"
revision_history:
  - revision: 2
    at: "2026-11-06T04:43:46Z"
    checksum: sha256:840573b6d5f2b9c712f72a488324578d33d4dea369c8e463c5666bbed1afae97
    summary: poc_available
    changed_fields:
      - claim_state
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=9E64B1AD-0E1A-563F-9D46-8EABA06936E2&utm_source=rss&utm_medium=rss
title: 'MacCMS: Authentication bypass in password recovery (CVE-2026-116214)'
slug: 2026-10-maccms-auth-bypass
description: MacCMS v10 before 2026.1000.4054 contains an authentication bypass vulnerability in the password recovery function that allows unauthenticated attackers to hijack arbitrary user accounts.
date: "2026-10-26T15:43:34Z"
lastmod: "2026-11-06T04:37:49Z"
type: advisory
claim_state: <nil>
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
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=9E64B1AD-0E1A-563F-9D46-8EABA06936E2&utm_source=rss&utm_medium=rss
vendors:
  - MacCMS
products:
  - MacCMS (v10 < 2026.1000.4054)
cves:
  - id: CVE-2026-116214
    cvss: 9.1
    epss: 0.00458
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116214
  - https://sploitus.com/exploit?id=9E64B1AD-0E1A-563F-9D46-8EABA06936E2&utm_source=rss&utm_medium=rss
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
updates:
  - at: "2026-11-06T04:37:49Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=9E64B1AD-0E1A-563F-9D46-8EABA06936E2&utm_source=rss&utm_medium=rss
---

MacCMS v10 versions prior to 2026.1000.4054 contain a critical vulnerability in the password reset process. The `check_msg()` function fails to validate the `msg_to` parameter during password recovery, enabling an attacker to bypass authentication. An attacker can initiate a password recovery request for a target account, intercept the recovery code sent to their own controlled address, and submit that code to the `user/findpass_reset` endpoint with the victim's email or phone number to change the password and gain unauthorized access.

## Impact

Successful exploitation allows unauthenticated attackers to gain full control over any member account, potentially leading to unauthorized data access or administrative account compromise.

## Recommendation

* Patch MacCMS v10 to version 2026.1000.4054 or later immediately.
* Audit web server logs for suspicious spikes in requests to `user/findpass_msg` and `user/findpass_reset` from single source IPs, which may indicate automated account takeover attempts.
