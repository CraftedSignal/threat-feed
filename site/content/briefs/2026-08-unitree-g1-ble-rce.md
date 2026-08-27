---
title: Unitree G1 EDU Firmware BLE Authentication Bypass and RCE
slug: 2026-08-unitree-g1-ble-rce
description: Unitree G1 EDU firmware versions 1.5.2 and earlier contain a chained vulnerability in the BLE GATT server and WiFi provisioning stack, allowing unauthenticated proximate attackers to achieve root-level remote code execution.
date: "2026-08-27T21:10:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - iot
  - rce
  - vulnerability
  - bluetooth
vendors:
  - Unitree
products:
  - G1 EDU firmware
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1211
    technique_name: Exploitation for Defense Evasion
    evidence: An unauthenticated proximate attacker can leverage a buffer overflow in the SSID chunk accumulator to corrupt a function pointer, leading to root-level remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1566
    technique_name: Phishing
    evidence: This exploit occurs during the WiFi provisioning process, bypassing authentication requirements.
    confidence_band: high
cves:
  - id: CVE-2026-76640
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76640
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Review inventory for active Unitree G1 EDU deployments.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-76640 impact on G1 EDU firmware.
  mitigation_plan:
    - priority: immediate
      action: Disable BLE functionality on robots if not required for operational mission.
      owner: IT Operations
      addresses: CVE-2026-76640
      evidence: BLE GATT server vulnerability.
---

Unitree G1 EDU firmware through version 1.5.2 is susceptible to a high-severity remote code execution vulnerability (CVE-2026-76640) residing within the Bluetooth Low Energy (BLE) GATT server and the associated WiFi provisioning stack. An unauthenticated attacker in physical proximity to the device can leverage this vulnerability to execute arbitrary commands with root privileges. The attack chain involves sending crafted BLE write requests to trigger a buffer overflow in the SSID chunk accumulator, subsequently corrupting a mainloop function pointer dispatch entry. This corrupted pointer is later invoked during a cleanup sequence, which results in the execution of attacker-supplied data via the system() call as uid 0. This vulnerability is significant as it permits complete device compromise without the need for prior pairing, credentials, or user interaction during the WiFi provisioning process.

## Attack Chain

1. Attacker identifies a Unitree G1 EDU device with active BLE advertising enabled.
2. Attacker establishes a connection to the device's BLE GATT server.
3. Attacker sends a series of crafted BLE write requests containing malicious SSID payloads.
4. The SSID chunk accumulator buffer is overflowed due to insufficient size validation.
5. The overflow corruption overwrites an adjacent mainloop function pointer dispatch entry in memory.
6. The firmware triggers a cleanup routine that calls the now-corrupted function pointer.
7. Attacker-controlled data is passed to the system() function, resulting in arbitrary code execution with root privileges (uid 0).

## Impact

Successful exploitation grants an attacker full control over the Unitree G1 EDU robot, including the ability to manipulate robot movement, access onboard sensors, and exfiltrate data. Given the device's role in educational and research environments, this could lead to the compromise of local network access via the WiFi provisioning vector or the deployment of persistent malicious firmware.

## Recommendation

1. Restrict physical and wireless proximity to authorized personnel for all Unitree G1 EDU units.
2. Monitor for firmware update availability from Unitree and prioritize patching to a version beyond 1.5.2.
3. Implement network-level segmentation to limit the impact of compromised robots attempting to move laterally into sensitive infrastructure.
4. Audit logs for anomalous BLE connection attempts or repeated service crashes that may indicate exploitation attempts.
