---
title: BlueZ Denial of Service Vulnerability
slug: 2026-10-bluez-dos
description: A vulnerability in the BlueZ Bluetooth stack allows a remote, unauthenticated attacker to trigger a denial-of-service condition on affected Linux systems.
date: "2026-10-14T16:26:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:bluez:bluez:*:*:*:*:*:*:*:*
vendors:
  - BlueZ
products:
  - bluez
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: An unauthenticated attacker can exploit the vulnerability to cause a denial-of-service condition.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3912
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update bluez package to the latest version via distribution package manager
      owner: IT Operations
      due: 72h
      evidence: CVE-2024-8390 requires patching to remediate the vulnerability
  mitigation_plan:
    - priority: immediate
      action: Patch CVE-2024-8390 in the bluez stack
      owner: IT Operations
      addresses: CVE-2024-8390
      evidence: Source advisory states the service is unpatched and vulnerable
---

The BlueZ Bluetooth stack for Linux contains a security vulnerability, identified as CVE-2024-8390, which can be exploited by a remote, unauthenticated attacker. The flaw allows for the initiation of a Denial of Service (DoS) attack, potentially causing the Bluetooth subsystem or the affected system to become unresponsive or crash. This issue is particularly relevant for Linux-based devices that have Bluetooth enabled and are reachable by unauthorized parties within physical range. Defenders should prioritize auditing the BlueZ version currently in use across their infrastructure and monitoring for updates from their respective Linux distributions, as this vulnerability represents a stable entry point for service disruption without requiring user interaction or prior credentials.

## Impact

The vulnerability poses a risk of service disruption for any Linux system utilizing the affected BlueZ versions. If an attack succeeds, the Bluetooth subsystem may become unusable, requiring a service restart or a full system reboot, which can impact availability in environments relying on Bluetooth for critical connectivity or local device management.

## Recommendation

Prioritize updating the bluez package to the latest version provided by your Linux distribution security repositories to address CVE-2024-8390. Monitor system logs for repeated Bluetooth service failures or unusual crash patterns in the bluetoothd process.
