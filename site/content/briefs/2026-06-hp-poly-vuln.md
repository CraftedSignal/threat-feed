---
title: HP Security Advisory for Poly Voice Vulnerability
slug: 2026-06-hp-poly-vuln
description: HP released a security advisory addressing a critical vulnerability in Poly VVX, Trio 8300, Trio 8500, and Trio 8800 devices, potentially allowing remote control.
date: "2026-06-02T15:28:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - hp
  - poly
  - voip
  - remote-control
vendors:
  - HP
products:
  - Poly VVX (versions prior to UCS 6.4.8)
  - Poly Trio 8300 (versions prior to UCS 8.1.7)
  - Poly Trio 8500 (versions prior to UCS 7.2.8)
  - Poly Trio 8800 (versions prior to UCS 7.2.8)
references:
  - https://cyber.gc.ca/en/alerts-advisories/hp-security-advisory-av26-539
  - https://support.hp.com/us-en/document/ish_15052661-15052687-16/hpsbpy04083
rules:
  - title: Detect Unauthorized Access Attempts to Poly Devices
    description: Detects attempts to gain unauthorized access to Poly devices by monitoring network traffic for suspicious patterns.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1595
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious Command Execution Attempts
    description: Detects suspicious command execution attempts by monitoring process creation for unusual processes originating from Poly device IP addresses.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On June 1, 2026, HP published security advisory AV26-539 regarding a critical vulnerability affecting several Poly voice and conferencing devices. The impacted products include HP Poly VVX (versions prior to UCS 6.4.8), HP Poly Trio 8300 (versions prior to UCS 8.1.7), HP Poly Trio 8500 (versions prior to UCS 7.2.8), and HP Poly Trio 8800 (versions prior to UCS 7.2.8). The advisory indicates a potential for remote control of affected devices. Defenders should review the HP advisory and apply the necessary updates as soon as they are available to mitigate the risk. Due to the nature of VoIP devices and their presence on corporate networks, a successful exploit could lead to significant disruption or unauthorized access.

## Attack Chain

1.  Attacker identifies vulnerable Poly device on the network.
2.  Attacker leverages the vulnerability to gain unauthorized access to the device.
3.  Attacker executes arbitrary commands on the device.
4.  Attacker gains control of the device's audio and video functionalities.
5.  Attacker monitors or intercepts communications taking place via the device.
6.  Attacker uses the compromised device as a pivot point to access other systems on the network.

## Impact

A successful exploit could allow an attacker to remotely control Poly voice devices, potentially intercepting sensitive communications. The number of affected devices is currently unknown, but the vulnerability is considered critical due to the potential for widespread exploitation across various sectors that rely on these devices for conferencing and communication. Successful exploitation can lead to data breaches, eavesdropping, and further network compromise.

## Recommendation

*   Review the HP security advisory linked in the references for detailed information about the vulnerability and affected products.
*   Apply the necessary updates to HP Poly VVX devices to version UCS 6.4.8 or later.
*   Apply the necessary updates to HP Poly Trio 8300 devices to version UCS 8.1.7 or later.
*   Apply the necessary updates to HP Poly Trio 8500 and 8800 devices to version UCS 7.2.8 or later.
