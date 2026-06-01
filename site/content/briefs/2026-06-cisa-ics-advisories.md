---
title: CISA ICS Advisories Address Vulnerabilities in Multiple Vendor Products
slug: 2026-06-cisa-ics-advisories
description: CISA published ICS advisories between May 25 and 31, 2026, addressing vulnerabilities across various vendors including ABB, CP Plus, Eppendorf, Frontier, Jinan USR IOT, KMW, MacGregor, Schneider Electric, and XCharge, impacting industrial control systems and related applications.
date: "2026-06-01T13:20:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ics
  - vulnerability
  - cisa
vendors:
  - ABB
  - CP Plus
  - Eppendorf
  - Frontier
  - Jinan USR IOT Technology Limited
  - KMW
  - MacGregor
  - Schneider Electric
  - XCharge
products:
  - AC500 V2
  - Ability Camera Connect
  - Ability Zenon
  - B&R Automation Runtime
  - EIBPORT V3 KNX (2CLA963710W1001)
  - EIBPORT V3 KNX GSM (2CLA963720W1001)
  - LVS MConfig
  - 8 Ch. Network Video Recorder
  - BioFlo 320
  - X Android application
  - X IOS application
  - X2
  - USR-W610 RS232/485 to Wi-Fi/Ethernet Converter
  - CCTV Security Cameras
  - Voyage Data Recorder (VDR) G4e
  - EcoStruxure Machine Expert HVAC
  - Switch Actuator 4 DU
  - Switch Actuator, door/light 4 DU
  - Terra AC Wallbox
  - C6
affected_os:
  - Android
  - iOS
references:
  - https://cyber.gc.ca/en/alerts-advisories/control-systems-cisa-ics-security-advisories-av26-530
  - https://www.cisa.gov/news-events/ics-advisories
rules:
  - title: ICS Application Spawning Suspicious Processes
    description: Detects unusual processes spawned by ICS applications, potentially indicating exploitation or malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: ICS Application Network Connections to External IPs
    description: Detects network connections from ICS applications to external IP addresses, potentially indicating command and control or data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Between May 25 and 31, 2026, CISA released multiple ICS advisories addressing vulnerabilities in a range of industrial control systems and related products. The advisories cover products from vendors including ABB, CP Plus, Eppendorf, Frontier, Jinan USR IOT Technology Limited, KMW, MacGregor, Schneider Electric, and XCharge. The affected products include industrial controllers, cameras, automation software, network video recorders, scientific equipment, mobile applications, converters, security cameras, voyage data recorders, HVAC systems, actuators, and charging stations. These vulnerabilities, if exploited, could allow attackers to disrupt critical processes, gain unauthorized access, or cause damage to equipment. Defenders should review the advisories for specific CVEs (where applicable in the original CISA advisories) and apply the recommended mitigations to secure their environments.

## Attack Chain

Due to the broad nature of this advisory covering vulnerabilities in multiple disparate products, a generalized attack chain is described below:

1. **Initial Access:** An attacker identifies a vulnerable ICS product or application accessible either directly or through network pivoting.
2. **Exploitation:** The attacker exploits a vulnerability (e.g., remote code execution, authentication bypass, or information disclosure) in the targeted product, based on the specific CVE details.
3. **Privilege Escalation:** The attacker escalates privileges within the compromised system, potentially leveraging additional vulnerabilities or misconfigurations.
4. **Lateral Movement:** The attacker moves laterally through the OT network, compromising additional ICS devices and systems.
5. **Command and Control:** The attacker establishes a command and control channel to maintain access and control over the compromised environment.
6. **Impact:** The attacker manipulates ICS processes, causing disruption, damage, or theft of sensitive information. This could involve actions such as modifying setpoints, shutting down equipment, or altering control logic.

## Impact

Successful exploitation of these vulnerabilities can lead to significant disruptions in industrial operations, potential physical damage to equipment, and compromise of sensitive data. The affected products span various sectors, including manufacturing, energy, transportation, and healthcare. The impact can range from temporary service outages to long-term operational disruptions, depending on the criticality of the affected systems.

## Recommendation

*   Review the CISA ICS advisories linked in the references and identify the specific vulnerabilities affecting your environment.
*   Apply the recommended mitigations provided in the advisories, including patching affected products to the latest versions.
*   Segment your OT network to limit the impact of a potential breach, as mentioned in the overview.
*   Monitor network traffic for suspicious activity related to the affected products (e.g., unusual communication patterns, unauthorized access attempts) to proactively identify and respond to potential attacks.
*   Deploy the generic Sigma rule provided in this brief for process monitoring on systems where ICS applications run to detect unusual activity.
