---
title: Katana Mirai Variant Targeting Android TV Devices
slug: 2024-01-katana-mirai-variant
description: Katana is a Mirai botnet variant that infects Android TV set-top boxes and compiles its own rootkit for persistence and control.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mirai
  - botnet
  - android
  - rootkit
vendors:
  - Google
products:
  - Android TV
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://www.reddit.com/r/blueteamsec/comments/1rwgevc/katana_a_mirai_variant_that_compiles_its_own/
  - https://github.com/deepfield/public-research/blob/main/katana/report.md
rules:
  - title: Detect Android Device Downloading Executables via Wget/Curl
    description: Detects Android devices downloading executable files using wget or curl, which may indicate malware installation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1105
    data_sources:
      - network_connection
      - linux
  - title: Detect Compilation Activity on Android
    description: Detects execution of compiler tools like gcc on Android devices, which could indicate rootkit compilation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The Katana botnet is a variant of the notorious Mirai malware specifically designed to target Android TV set-top boxes. First identified in late 2025, Katana distinguishes itself from other Mirai variants by its ability to compile its own rootkit directly on infected devices. This allows the malware to achieve persistent access and evade detection more effectively. The delivery mechanism for Katana is still under investigation, but it is suspected to leverage vulnerabilities in older Android TV firmware versions or exploit weak default credentials. The primary purpose of Katana is to recruit devices into a botnet for distributed denial-of-service (DDoS) attacks and potentially other malicious activities.

## Attack Chain

1.  Initial Access: The attacker exploits a vulnerability in the Android TV device's firmware or uses default credentials to gain initial access.
2.  Payload Delivery: The attacker uploads the Katana Mirai variant binary to the compromised device using wget or curl.
3.  Compilation Tools: The malware leverages pre-existing tools or downloads necessary compilation tools (e.g., gcc) to the device.
4.  Rootkit Compilation: Katana compiles its own rootkit from source code on the device. This rootkit is designed for the specific Android TV device's architecture.
5.  Persistence: The compiled rootkit is installed to ensure the malware persists across reboots and system updates. The rootkit modifies system files to auto-start the Mirai binary.
6.  Command and Control: The infected device connects to a command-and-control (C2) server to receive instructions and participate in DDoS attacks.
7.  Lateral Movement: The bot attempts to spread to other devices on the same network using known exploits or default credentials.

## Impact

A successful Katana infection results in the compromised Android TV device being added to a botnet, capable of participating in DDoS attacks and other malicious activities. Infected devices may experience performance degradation, increased network traffic, and potential exposure of sensitive user data. While the exact number of victims is currently unknown, the botnet has the potential to affect a large number of users given the widespread use of Android TV devices.

## Recommendation

*   Monitor network traffic for connections to known Mirai C2 servers (reference open-source threat intelligence feeds).
*   Deploy the Sigma rules provided in this brief to your SIEM to detect potential Katana infections.
*   Implement network segmentation to limit the lateral movement of compromised devices.
*   Encourage users to change default credentials on their Android TV devices and keep their firmware updated to the latest version.
