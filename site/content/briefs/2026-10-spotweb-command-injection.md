---
title: Remote Code Execution via OS Command Injection in Spotweb
slug: 2026-10-spotweb-command-injection
description: Spotweb versions 1.5.8 and earlier are vulnerable to remote code execution through the NZB handler, triggered by maliciously crafted Usenet spot titles.
date: "2026-10-10T15:55:12Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:spotweb:spotweb:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - remote-code-execution
  - command-injection
vendors:
  - Spotweb
products:
  - Spotweb (<= 1.5.8)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can post self-signed spots over Usenet with shell metacharacters in the title, which are substituted unescaped for $SPOTTITLE and passed to exec() when a user downloads the spot.
    confidence_band: high
cves:
  - id: CVE-2026-108546
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108546
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Spotweb to latest secure version
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-108546 necessitates software update
  mitigation_plan:
    - priority: immediate
      action: Upgrade Spotweb to version post-1.5.8
      owner: IT Operations
      addresses: CVE-2026-108546
      evidence: Source states vulnerability exists through 1.5.8
---

Spotweb versions 1.5.8 and earlier contain a critical OS command injection vulnerability located within the application's NZB handler. The vulnerability stems from the unsafe handling of user-supplied spot titles retrieved from Usenet. An attacker can create a spot with a title containing shell metacharacters and publish it to the Usenet network. When a target user processes or downloads this specific spot, the Spotweb application substitutes the malicious title into the $SPOTTITLE variable, which is then passed directly to the PHP exec() function without proper sanitization. This results in the execution of arbitrary commands on the underlying host with the privileges of the web server process. This vulnerability is significant for defenders as it allows for unauthenticated remote code execution triggered by standard user interaction with the application interface.

## Impact

Successful exploitation allows for remote code execution, which can lead to full system compromise, data theft, and persistence within the victim's environment. The scope of impact is limited to organizations and individuals running self-hosted Spotweb instances up to version 1.5.8. Because the exploit relies on the processing of Usenet content, any internet-facing Spotweb installation is at risk if configured to sync with public Usenet indices.

## Recommendation

Prioritized actions for detection and mitigation:
- Immediately upgrade Spotweb instances to a version beyond 1.5.8 or apply the vendor-supplied security patch to remediate CVE-2026-108546.
- Audit PHP execution logs to monitor for unexpected calls originating from the NZB handler component or unusual child processes spawned by the web server service.
- Implement strict egress filtering on the host machine to prevent the web server process from initiating outbound connections to unauthorized external IP addresses.
