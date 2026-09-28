---
title: Remote Stack-Based Buffer Overflow in FAST FAC1200R devdiscover Service
slug: 2026-09-fast-fac1200r-overflow
description: A critical stack-based buffer overflow vulnerability in the devdiscover service of FAST FAC1200R routers allows unauthenticated remote attackers to achieve code execution via malformed advertisement frames.
date: "2026-09-28T12:14:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:o:fast:fac1200r_firmware:5.0_20201119_1.0.2:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - buffer-overflow
  - network-infrastructure
vendors:
  - FAST
products:
  - FAC1200R (5.0_20201119_1.0.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: The manipulation results in stack-based buffer overflow and the attack may be launched remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: The vulnerability allows for remote code execution by an unauthenticated attacker.
    confidence_band: high
cves:
  - id: CVE-2026-101037
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101037
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Isolate affected FAST FAC1200R devices from public network exposure.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-101037 provides remote exploitation vector.
  mitigation_plan:
    - priority: immediate
      action: Restrict management interface access via firewall or ACL.
      owner: IT Operations
      addresses: CVE-2026-101037
      evidence: Public exploit code is available for this remote vulnerability.
---

A critical stack-based buffer overflow vulnerability, identified as CVE-2026-101037, has been disclosed in the FAST FAC1200R router, specifically within the `parse_advertisement_frame` function of the `devdiscover` service. This vulnerability, affecting version 5.0_20201119_1.0.2, allows unauthenticated remote attackers to trigger a crash or potentially execute arbitrary code by sending a specially crafted advertisement frame to the device. Public exploit code for this vulnerability is currently available, significantly increasing the risk of exploitation. The vendor has reportedly failed to respond to disclosure attempts, leaving affected systems without a patch. Defenders should prioritize identifying exposed router interfaces and restricting access to the `devdiscover` service management ports to prevent remote exploitation.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated, remote attacker to gain control over the affected network device. Given that the device is a router, this provides a foothold for further lateral movement into the internal network, traffic interception, or the establishment of persistent backdoors. As the vendor has not released a patch, affected organizations face a sustained risk of remote code execution.

## Recommendation

- Perform an immediate audit to identify all FAST FAC1200R devices exposed to the internet.
- Implement network-level access controls to restrict access to management services on these devices to authorized management IP addresses only.
- Monitor network traffic for anomalous advertisement frames directed at router management interfaces.
- Given the lack of a vendor patch, evaluate replacing affected hardware with models currently receiving active security support.
