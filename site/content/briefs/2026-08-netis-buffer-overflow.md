---
title: Remote Code Execution in Netis NC63 Firmware via Buffer Overflow
slug: 2026-08-netis-buffer-overflow
description: A stack-based buffer overflow in the Netis NC63 login handler allows unauthenticated remote attackers to achieve root-level code execution.
date: "2026-08-24T18:03:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - network-device
  - buffer-overflow
vendors:
  - Netis
products:
  - NC63
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Netis NC63 firmware through V3.0.0.3327 contains a stack-based buffer overflow vulnerability that allows unauthenticated remote attackers to overwrite saved stack state by submitting an oversized Base64-encoded password to the login handler in /bin/netis.cgi.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76070
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Review inventory for Netis NC63 devices and verify firmware version status
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-76070 vulnerability notice
  mitigation_plan:
    - priority: immediate
      action: Restrict management interface access via network ACLs
      owner: IT Operations
      addresses: CVE-2026-76070
      evidence: Unauthenticated remote exploit vector
---

Netis NC63 firmware versions through V3.0.0.3327 contain a high-severity stack-based buffer overflow vulnerability, identified as CVE-2026-76070. The flaw resides within the login handler of the `/bin/netis.cgi` binary, which utilizes a custom Base64 decoding implementation. Due to the absence of proper length validation during the decoding process, an attacker can supply an oversized Base64-encoded password string to trigger a memory corruption event. 

The overflow occurs on a fixed-size stack buffer, enabling the attacker to overwrite the saved stack state and control the program execution flow. Because the underlying Boa web server operates with root privileges, this exploit results in full system compromise. This vulnerability is significant due to the lack of authentication required to reach the vulnerable code path and the resulting elevated execution context, posing a critical risk to affected network devices.

## Impact

Successful exploitation allows unauthenticated remote attackers to gain root-level access to the affected Netis NC63 routers. This enables full device control, potential persistent access, lateral movement within the local network, and interception of sensitive traffic traversing the gateway.

## Recommendation

* Immediately upgrade Netis NC63 firmware to a version beyond V3.0.0.3327 if a patch is provided by the vendor.
* If patching is not immediately feasible, restrict access to the web management interface of the Netis NC63 to trusted IP addresses only, using firewall rules.
* Monitor network traffic directed toward the web management port (typically 80 or 443) for unusually large or malformed strings sent to `netis.cgi`.
