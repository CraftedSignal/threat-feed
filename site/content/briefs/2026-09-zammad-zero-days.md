---
title: Active Exploitation of Zammad Remote Code Execution and Privilege Escalation Vulnerabilities
slug: 2026-09-zammad-zero-days
description: Zammad helpdesk software is being actively exploited via two zero-day vulnerabilities, including an unauthenticated RCE (CVE-2026-102489) and an unpatched privilege escalation flaw (CVE-2026-102490).
date: "2026-09-30T19:45:40Z"
lastmod: "2026-10-01T14:14:25Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:a:zammad:zammad:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - privilege-escalation
  - webserver
vendors:
  - Zammad
products:
  - Zammad (6.3.0 - 6.5.4)
  - Zammad (all current versions)
  - Zammad
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability, with characteristic CVE-2026-102489, makes it possible for an attacker to execute malicious code remotely without logging in.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The vulnerability, with characteristic CVE-2026-102490, allows an attacker with limited access to obtain the highest administrator rights (root rights) on the system.
    confidence_band: high
cves:
  - id: CVE-2026-102490
    epss: 0.00319
  - id: CVE-2026-102489
    epss: 0.00709
references:
  - https://www.ncsc.nl/alerts/actief-misbruik-van-zeroday-kwetsbaarheden-in-zammad-update-nu
  - https://www.securityweek.com/zammad-zero-days-exploited-in-ai-powered-divd-hack/
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3694
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Zammad instances affected by CVE-2026-102489
      owner: IT Operations
      due: 24h
      evidence: Zammad has released a security update for the first vulnerability.
  enrichment_needed:
    - item: CVE-2026-102490
      owner: CTI
      reason: Monitor for patch release or vendor workaround advice
      evidence: The second vulnerability (CVE-2026-102490) has not yet been resolved.
  mitigation_plan:
    - priority: immediate
      action: Backup application logs prior to patching
      owner: IT Operations
      addresses: CVE-2026-102489 and CVE-2026-102490
      evidence: Make a copy of the application and network logs before installing the update.
updates:
  - at: "2026-10-01T14:14:25Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3694
---

Since September 21, 2026, threat actors have been actively exploiting two zero-day vulnerabilities within Zammad, a widely used helpdesk and customer support software. The first vulnerability, CVE-2026-102489, is a critical remote code execution (RCE) flaw that allows unauthenticated attackers to execute arbitrary code on the underlying server. This issue affects Zammad versions 6.3.0 through 6.5.4 and has been addressed with a security update.

The second vulnerability, CVE-2026-102490, allows an attacker with limited access to elevate their privileges to root, granting full system control. This vulnerability currently affects all current versions of Zammad and remains unpatched as of September 30, 2026. Given the active exploitation observed in the wild, organizations running Zammad are at high risk of complete system compromise, data theft, and persistent unauthorized access. Defenders must prioritize patching the RCE vulnerability and monitoring for unauthorized privilege escalation attempts.

## Attack Chain

1. Attacker performs reconnaissance to identify public-facing instances of Zammad.
2. Attacker sends specially crafted, unauthenticated HTTP requests to exploit CVE-2026-102489.
3. The target Zammad server processes the malicious request, resulting in remote code execution (RCE) with the privileges of the web service account.
4. Attacker executes post-exploitation commands to download additional tooling or establish persistence.
5. Attacker leverages the limited-privilege shell to exploit CVE-2026-102490.
6. The vulnerability in Zammad allows the attacker to escalate to root privileges.
7. Attacker gains full system control, facilitating data exfiltration, modification, or further lateral movement within the network.

## Impact

Successful exploitation of these vulnerabilities allows for unauthenticated remote code execution and full root privilege escalation on Zammad instances. This provides attackers with complete control over customer support data, communication logs, and internal credentials stored within the application. Given the nature of helpdesk platforms, compromised systems may serve as a significant pivot point for broader organizational network intrusion. Active exploitation has been confirmed since September 21, 2026, posing a critical risk to all sectors utilizing Zammad.

## Recommendation

* Apply the security update provided by Zammad for CVE-2026-102489 immediately across all instances of versions 6.3.0 through 6.5.4.
* For CVE-2026-102490, since no patch is currently available, increase monitoring of administrative account logins and unauthorized process execution originating from the Zammad application user.
* Before applying updates, export and secure application and network logs as recommended by the NCSC to facilitate forensic analysis should evidence of exploitation be discovered.
* Coordinate with IT-service providers to verify the current version of Zammad installations and assess exposure risk.
