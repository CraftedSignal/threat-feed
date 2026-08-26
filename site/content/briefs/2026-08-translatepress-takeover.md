---
title: Unauthenticated Account Takeover in TranslatePress Plugin
slug: 2026-08-translatepress-takeover
description: CVE-2026-19632 allows unauthenticated attackers to hijack user accounts in the TranslatePress - Multilingual WordPress plugin via password reset link disclosure.
date: "2026-08-26T15:23:40Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - wordpress
  - plugin-vulnerability
  - account-takeover
products:
  - TranslatePress - Multilingual (<= 3.3.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated account takeover in TranslatePress <= 3.3.1 via password reset link disclosure.
    confidence_band: high
references:
  - https://sploitus.com/exploit?id=65A1E120-68EC-5FE9-87C4-0F2DCF2BE10D
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch TranslatePress - Multilingual plugin to latest version
      owner: IT Operations
      due: 24h
      evidence: Critical severity vulnerability with public PoC
  hunt_leads:
    - lead: Unusual spikes in requests to password reset or account management endpoints
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation involves manipulating password reset logic
---

CVE-2026-19632 is a critical vulnerability affecting the TranslatePress - Multilingual WordPress plugin in versions 3.3.1 and earlier. The vulnerability stems from an insecure implementation that leads to the disclosure of password reset links to unauthenticated users. By successfully triggering this flaw, an attacker can obtain the reset token for any user, including administrative accounts, allowing for complete account takeover. 

This vulnerability carries a CVSS score of 9.8, indicating it is easily exploitable over the network without requiring prior authentication or user interaction. Multiple proof-of-concept exploits have been published as of August 26, 2026, significantly increasing the risk of active exploitation against WordPress installations utilizing this plugin. Defenders should prioritize updating to a patched version immediately.

## Attack Chain

1. Attacker performs reconnaissance to identify WordPress sites running vulnerable versions of the TranslatePress plugin.
2. Attacker probes the target application to identify endpoints related to the password reset functionality.
3. Attacker crafts an HTTP request targeting the vulnerable plugin logic (CVE-2026-19632) to trigger an unintended password reset action.
4. The vulnerable plugin discloses the password reset token or link in the application response due to the underlying logic flaw.
5. Attacker intercepts the reset link or token from the server response.
6. Attacker uses the captured link to reset the target account password.
7. Attacker logs into the hijacked account, achieving full unauthorized access.

## Impact

Successful exploitation allows unauthenticated attackers to gain complete access to any user account within a WordPress site, including accounts with administrative privileges. This can lead to total site compromise, data exfiltration, injection of malicious content, and persistent unauthorized access to the affected environment.

## Recommendation

- Immediately update the TranslatePress - Multilingual plugin to the latest version.
- Audit WordPress user logs for suspicious password reset requests or unauthorized account access patterns.
- Review administrative user accounts for recent changes or unexpected login activity.
- Monitor web application logs for high volumes of traffic directed at password reset-related endpoints if remediation is delayed.
