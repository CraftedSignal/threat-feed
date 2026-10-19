---
title: Authentication Bypass in eremef bandcamp-player
slug: 2026-10-bandcamp-player-auth-bypass
description: A missing authentication vulnerability in the Remote Control Server component of eremef bandcamp-player allows remote attackers to bypass security controls via the remoteEnabled argument.
date: "2026-10-19T12:03:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:eremef:bandcamp-player:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - cve-2026-112104
vendors:
  - eremef
products:
  - bandcamp-player (<= 1.8.33-beta)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1595
    technique_name: Active Scanning
    evidence: The attack may be launched remotely.
    confidence_band: med
cves:
  - id: CVE-2026-112104
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112104
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade bandcamp-player to 1.8.34-beta or later
      owner: IT Operations
      due: 24h
      evidence: Upgrading to version 1.8.34-beta is sufficient to resolve this issue.
  mitigation_plan:
    - priority: immediate
      action: Patch CVE-2026-112104 by updating bandcamp-player to 1.8.34-beta
      owner: IT Operations
      addresses: CVE-2026-112104
      evidence: Upgrading to version 1.8.34-beta is sufficient to resolve this issue.
---

A security vulnerability identified as CVE-2026-112104 affects the eremef bandcamp-player software package in versions up to and including 1.8.33-beta. The flaw resides within the Remote Control Server component, specifically in an undisclosed function within the database.ts file. An attacker can exploit this by manipulating the remoteEnabled argument, leading to a bypass of authentication mechanisms. Because the attack can be executed remotely, it poses a significant risk to the integrity of affected systems. The vulnerability is resolved in version 1.8.34-beta, which includes the fix referenced by commit ccba99b66bc61acf46e4a332034799d7452ddea6. Organizations utilizing this package are urged to update to the latest version to prevent unauthorized remote access to the Remote Control Server.

## Impact

Successful exploitation allows an unauthenticated remote attacker to bypass authentication controls within the Remote Control Server. This could lead to unauthorized administrative access or control over the server functionality, potentially enabling further exploitation or data exposure depending on the specific implementation of the remote control features.

## Recommendation

Update the eremef bandcamp-player component to version 1.8.34-beta or later immediately. Ensure that the Remote Control Server feature is not exposed to untrusted networks until the software has been patched to the remediated version.
