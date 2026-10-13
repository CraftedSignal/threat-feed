---
title: Remote Command Injection in Wavlink WL-WN592AX6
slug: 2026-10-wavlink-rce
description: The wmapd daemon in Wavlink WL-WN592AX6 firmware version 250422 is vulnerable to remote, unauthenticated OS command injection, allowing full device takeover.
date: "2026-10-13T10:34:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:o:wavlink:wl-wn592ax6_firmware:250422:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - command-injection
  - iot
  - router
  - network-infrastructure
vendors:
  - Wavlink
products:
  - WL-WN592AX6 (250422)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to launch the attack remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Executing a manipulation can lead to os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-109110
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109110
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
  immediate_actions:
    - action: Restrict external access to management interfaces of Wavlink WL-WN592AX6
      owner: SOC
      due: 24h
      evidence: Unauthenticated remote OS command injection vulnerability
  mitigation_plan:
    - priority: immediate
      action: Patch Wavlink WL-WN592AX6 firmware if a newer version is available
      owner: IT Operations
      addresses: CVE-2026-109110
      evidence: NVD advisory for CVE-2026-109110
---

A critical security flaw has been identified in the Wavlink WL-WN592AX6 router, specifically within the wmapd daemon component of firmware version 250422. This vulnerability allows an unauthenticated, remote attacker to trigger OS command injection via the system function. Because the device is an edge networking product, successful exploitation provides an attacker with complete control over the network traffic passing through the router, enabling man-in-the-middle attacks, credential harvesting, and pivoting into the internal network. Proof-of-concept exploit code for this vulnerability is publicly available, significantly increasing the likelihood of opportunistic exploitation by threat actors. Defenders should prioritize isolating affected hardware from the internet or restricting management interface access.

## Impact

Successful exploitation results in full remote compromise of the affected Wavlink WL-WN592AX6 router. Attackers can gain root-level access to the underlying operating system, potentially leading to persistent backdoors, data exfiltration from network traffic, and unauthorized access to local area network resources. This represents a critical risk to small office and home office (SOHO) environments utilizing this specific hardware and firmware version.

## Recommendation

- Restrict management interface access to the Wavlink WL-WN592AX6 to trusted internal management subnets only.
- Implement outbound traffic filtering on the router's host to detect and block suspicious call-home beacons.
- Monitor for unauthorized configuration changes or unexpected process execution within the router's environment if logging is available.
- Check for and apply firmware updates from Wavlink to remediate the vulnerable wmapd daemon.
