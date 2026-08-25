---
title: Arbitrary Code Execution in BlueZ Bluetooth Stack
slug: 2026-08-bluez-rce
description: A vulnerability in the BlueZ Bluetooth stack for Linux allows an unauthenticated attacker within Bluetooth range to execute arbitrary code with administrative privileges due to improper handling of Bluetooth requests.
date: "2026-08-25T09:59:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:aio-libs:aiosmtpd:*:*:*:*:*:*:*:*
vendors:
  - Linux Foundation
products:
  - BlueZ
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A vulnerability in the BlueZ Bluetooth stack for Linux allows an unauthenticated attacker within Bluetooth range to execute arbitrary code with administrative privileges.
    confidence_band: high
cves:
  - id: CVE-2024-27305
    cvss: 5.3
    epss: 0.00374
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2984
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch BlueZ across all Linux endpoints (CVE-2024-27305)
      owner: IT Operations
      due: 48h
      evidence: Source advisory WID-SEC-2026-2984
  mitigation_plan:
    - priority: immediate
      action: Disable bluetoothd service on non-essential systems
      owner: IT Operations
      addresses: CVE-2024-27305
      evidence: Proximity-based attack vector mitigation
---

The BlueZ Bluetooth protocol stack, the standard implementation for Linux systems, contains a critical vulnerability (CVE-2024-27305) that enables unauthenticated remote code execution. An attacker positioned within the physical Bluetooth transmission range can exploit this flaw by sending specifically crafted Bluetooth requests to the target device. Because the bluez daemon often operates with elevated privileges, successful exploitation grants the attacker administrative control over the underlying Linux host. This issue affects various Linux distributions utilizing the BlueZ stack and poses a significant risk to mobile devices, workstations, and IoT hardware that maintain persistent Bluetooth connectivity. Defenders should prioritize patching BlueZ to the latest version and, where feasible, disable Bluetooth services on sensitive systems until updates are applied.

## Impact

The vulnerability allows for full system compromise, enabling attackers to gain unauthorized access to data, install persistence mechanisms, or move laterally within a local network. It impacts a wide range of Linux-based devices, including workstations, mobile platforms, and embedded IoT systems that rely on the BlueZ stack for Bluetooth communication. 

## Recommendation

* Update the BlueZ package to the latest version provided by your Linux distribution to address CVE-2024-27305.
* Audit systems for active Bluetooth services and disable the `bluetoothd` service on servers or high-security endpoints where Bluetooth is not a required functional component.
* Use host-based firewall rules to restrict Bluetooth-related traffic where possible, although this does not mitigate the proximity-based nature of the attack.
