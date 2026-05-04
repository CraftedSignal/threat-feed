---
title: Qualcomm PLC FW Buffer Overflow via Incorrect Authorization (CVE-2026-25293)
slug: 2026-05-plc-buffer-overflow
description: CVE-2026-25293 is a critical buffer overflow vulnerability in Qualcomm PLC FW due to incorrect authorization, potentially allowing unauthorized access and control over programmable logic controllers.
date: "2026-05-04T17:16:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - plc
  - buffer-overflow
  - industrial-control-systems
  - cve-2026-25293
vendors:
  - Qualcomm
products:
  - PLC FW
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
cves:
  - id: CVE-2026-25293
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-25293
  - https://docs.qualcomm.com/product/publicresources/securitybulletin/may-2026-bulletin.html
rules:
  - title: Detect Suspicious Network Traffic to PLC Devices
    description: Detects suspicious network traffic patterns that may indicate exploitation attempts against PLC devices, specifically targeting buffer overflows.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1195
    data_sources:
      - network_connection
      - windows
  - title: Detect PLC FW Configuration File Modification
    description: Detects attempts to modify PLC FW configuration files, which could indicate unauthorized changes or malicious code injection.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

CVE-2026-25293 describes a buffer overflow vulnerability affecting Qualcomm's Programmable Logic Controller Firmware (PLC FW).  The root cause is an incorrect authorization mechanism within the firmware. This flaw could allow an attacker to potentially overwrite memory buffers, leading to arbitrary code execution or denial of service. The vulnerability was disclosed in Qualcomm's May 2026 security bulletin. Successful exploitation of this vulnerability could allow unauthorized modification of PLC configurations, potentially impacting industrial control systems and automation processes. The affected PLC FW is used in a range of industrial applications, increasing the scope and severity of this vulnerability.

## Attack Chain

1. Attacker identifies a vulnerable PLC FW device on the network.
2. The attacker leverages CVE-2026-25293 to bypass authorization checks.
3. A crafted network packet is sent to the PLC FW, exploiting the buffer overflow.
4. The overflowed buffer overwrites critical memory regions.
5. Attacker gains control of PLC FW execution flow.
6. Malicious code is injected into the PLC memory space.
7. The injected code executes, potentially modifying PLC logic or disrupting operations.
8. The attacker achieves unauthorized control over the PLC, leading to disruption, data manipulation, or system compromise.

## Impact

Successful exploitation of CVE-2026-25293 could allow attackers to gain complete control over Programmable Logic Controllers (PLCs). This could lead to significant disruptions in industrial control systems, manufacturing processes, and other automated systems. The vulnerability affects Qualcomm PLC FW, potentially impacting a large number of devices across various sectors. The high CVSS score of 9.6 reflects the critical impact of this vulnerability, including the potential for complete system compromise and denial of service.

## Recommendation

*   Apply the security patches provided by Qualcomm as detailed in their May 2026 security bulletin (https://docs.qualcomm.com/product/publicresources/securitybulletin/may-2026-bulletin.html) to remediate CVE-2026-25293.
*   Deploy the Sigma rule "Detect Suspicious Network Traffic to PLC Devices" to identify potential exploitation attempts.
*   Implement strict network segmentation to limit the attack surface and prevent lateral movement to PLC devices.
*   Monitor network traffic for unexpected patterns or unauthorized access attempts to PLC devices.
