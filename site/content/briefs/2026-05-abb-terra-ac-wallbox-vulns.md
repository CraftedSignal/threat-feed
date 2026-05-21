---
title: ABB Terra AC Wallbox Vulnerabilities Allow Remote Control and Firmware Alteration
slug: 2026-05-abb-terra-ac-wallbox-vulns
description: Multiple buffer overflow vulnerabilities in ABB Terra AC Wallbox versions <=1.8.33, exploitable via Bluetooth hijacking, could allow an attacker to remotely control the device and alter its firmware.
date: "2026-05-21T16:09:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ics
  - buffer overflow
  - cve-2025-10504
  - cve-2025-12142
  - cve-2025-12143
vendors:
  - ABB
products:
  - Terra AC wallbox
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
cves:
  - id: CVE-2025-10504
    cvss: 6.1
    epss: 0.00022
  - id: CVE-2025-12142
    cvss: 6.1
    epss: 0.00022
  - id: CVE-2025-12143
    cvss: 6.1
    epss: 0.00022
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-05
  - https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-141-05.json
  - https://www.cve.org/CVERecord?id=CVE-2025-10504
  - https://www.cve.org/CVERecord?id=CVE-2025-12142
  - https://www.cve.org/CVERecord?id=CVE-2025-12143
rules:
  - title: Generic Bluetooth Device Detection
    description: Detects connections to any Bluetooth device
    platform: sigma
    severity: low
    tactics:
      - discovery
    data_sources:
      - network_connection
      - windows
  - title: Detect Large data sent over Bluetooth
    description: Detects a large data transfers over a bluetooth interface. This could be used to exploit CVE-2025-10504, CVE-2025-12142, or CVE-2025-12143.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

ABB Terra AC Wallbox versions <=1.8.33 (JP) are susceptible to three buffer overflow vulnerabilities: CVE-2025-10504 (Heap-based), CVE-2025-12142 (Classic Buffer Overflow), and CVE-2025-12143 (Stack-based). Successful exploitation could lead to heap memory pollution, potentially enabling remote control of the device and unauthorized firmware modifications. While the advisory suggests Bluetooth hijacking is a prerequisite for exploitation due to encryption, the impact of a successful attack on charging infrastructure warrants attention from defenders. ABB has released version 1.8.36 to address these issues and recommends that customers apply the update at earliest convenience. These vulnerabilities are especially relevant to organizations in the energy sector, where these charging stations are deployed worldwide.

## Attack Chain

1. Attacker gains unauthorized access to the ABB Terra AC Wallbox via Bluetooth, bypassing encryption (e.g., through brute-force or vulnerability in the Bluetooth stack).
2. Attacker develops a custom application designed to communicate with the charging station using a self-defined protocol.
3. Attacker crafts a malicious message with an unexpected field length, specifically targeting the memory handling routines.
4. The crafted message triggers a heap-based buffer overflow (CVE-2025-10504), polluting the heap memory.
5. The memory corruption allows the attacker to overwrite critical data structures in memory.
6. The attacker leverages the corrupted memory to gain control of the device's execution flow.
7. The attacker performs a write operation to the flash memory, altering the device's firmware.
8. The compromised firmware enables the attacker to remotely control the charging station, potentially disrupting service or causing damage.

## Impact

Successful exploitation of these vulnerabilities could allow an attacker to remotely control ABB Terra AC Wallbox devices. This could lead to disruption of electric vehicle charging services, potentially impacting transportation and energy infrastructure. Altering the firmware could introduce malicious functionality, such as denial-of-service attacks or unauthorized access to the power grid. The vulnerabilities affect installations worldwide, with the most immediate concern being in the energy sector. While the advisory acknowledges the need to hijack Bluetooth first, the ability to overwrite firmware has significant implications.

## Recommendation

*   Apply the vendor-provided patch (Terra AC wallbox (JP) 1.8.36) to remediate CVE-2025-10504, CVE-2025-12142, and CVE-2025-12143 on affected ABB Terra AC Wallbox devices.
*   Monitor network traffic for suspicious Bluetooth activity targeting ABB Terra AC Wallbox devices, specifically looking for unexpected data lengths in custom protocol messages (Generic Bluetooth Detection Rule).
*   Implement network segmentation to isolate control system devices like the ABB Terra AC Wallbox from the internet and other business networks, as suggested by CISA.
