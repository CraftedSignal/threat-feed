---
brief_id: brief-2026-10-20-tplink-tapo-c320ws-rce
event_id: brief-2026-10-20-tplink-tapo-c320ws-rce
revision: 1
activity_at: "2026-10-20T18:42:16Z"
title: 'TP-Link Tapo C320WS: Stack-based buffer overflow RCE (CVE-2026-105810)'
slug: 2026-10-tplink-tapo-c320ws-rce
description: An authenticated stack-based buffer overflow in the TP-Link Tapo C320WS camera allows remote code execution as root via the Wi-Fi onboarding process.
date: "2026-10-20T18:42:16Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified against TP-Link advisory information.
cpes:
  - cpe:2.3:h:tp-link:tapo_c320ws:2.0:*:*:*:*:*:*:*
tags:
  - cve-2026-105810
  - rce
  - iot-security
vendors:
  - TP-Link
products:
  - Tapo C320WS (V2.0, <= 1.5.3 Build 260304)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated stack-based buffer overflow in the Wi-Fi onboarding path of the TP-Link Tapo C320WS camera.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Authenticated stack overflow in TP-Link Tapo C320WS connectAp enables RCE as root.
    confidence_band: high
cves:
  - id: CVE-2026-105810
    epss: 0.002
    kev_status: "false"
references:
  - https://www.tp-link.com/us/support/faq/5351/
  - https://sploitus.com/exploit?id=2ECCAD4A-5D06-5813-BA77-0D3B81E34BDF
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all TP-Link Tapo C320WS devices to firmware 1.6.6 Build 260917.
      owner: IT Operations
      due: 24h
      evidence: Fixed firmware listed in vendor advisory.
  hunt_leads:
    - lead: Identify devices on network running firmware older than 1.6.6.
      technique_id: T1190
      data_needed:
        - Asset management firmware version reporting
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerable firmware version range specified in source.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Tapo C320WS to firmware 1.6.6 Build 260917.
      owner: IT Operations
      addresses: CVE-2026-105810
      evidence: Vendor patch advisory.
---

CVE-2026-105810 is a high-severity, authenticated stack-based buffer overflow vulnerability affecting the TP-Link Tapo C320WS camera (hardware V2.0, firmware ≤ 1.5.3 Build 260304). The vulnerability resides in the `onboarding.connect` (`connectAp`) handler, which incorrectly calculates the destination capacity when base64-decoding a user-supplied Wi-Fi password. By providing an overly long, crafted password string, an authenticated administrative user on the adjacent network can overflow a fixed 1024-byte stack buffer. Because the vulnerable binary is a non-PIE ARM executable lacking stack canaries, an attacker can reliably execute arbitrary code as root by redirecting execution flow via a ROP chain to call `system()`. A functional proof-of-concept exploit is publicly available, necessitating immediate patching to firmware `1.6.6 Build 260917 Rel.81089n` or later.

## Attack Chain

1. Attacker gains administrative authentication to the target TP-Link Tapo C320WS local API.
2. Attacker interacts with the `onboarding.connect` (`connectAp`) handler via the device local management interface.
3. Attacker submits a specially crafted, base64-encoded Wi-Fi password string exceeding 1024 bytes.
4. The device decoder incorrectly determines buffer capacity, leading to memory corruption.
5. The stack-based buffer overflow overwrites the function return address on the stack.
6. The corrupted return address redirects the processor to an attacker-controlled ROP chain.
7. The ROP chain executes `system()` to run arbitrary commands on the underlying device.
8. Attacker gains full root command execution capabilities on the camera.

## Impact

Successful exploitation results in full remote command execution as the root user on the camera. This provides attackers with total control over the device, allowing them to intercept surveillance feeds, pivot into the local network, or use the camera as a foothold for further malicious activity. This vulnerability affects TP-Link Tapo C320WS cameras running firmware version 1.5.3 Build 260304 or earlier.

## Recommendation

* Patch all TP-Link Tapo C320WS cameras to firmware version `1.6.6 Build 260917 Rel.81089n` or later immediately.
* Implement network segmentation for IoT devices to restrict access to the camera's management API (TCP/443) to authorized administrative workstations only.
* Audit administrative account passwords and ensure strong credentials are used to prevent unauthorized access to the vulnerable API endpoints.
* Monitor network traffic originating from IoT segments for unexpected command execution patterns or ROP chain remnants if advanced network inspection is available.
