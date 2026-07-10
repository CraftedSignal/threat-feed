---
title: First Time Python Created a LaunchAgent or LaunchDaemon
slug: 2024-07-macos-python-launchagent
description: Detection of the first-time a Python process creates or modifies a LaunchAgent or LaunchDaemon plist file on a given macOS host, which is indicative of persistence attempts via malicious scripts, compromised dependencies, or model file deserialization.
date: "2024-07-03T14:27:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - macos
  - python
  - launchagent
  - launchdaemon
vendors:
  - Apple
  - Python Software Foundation
  - Meta Platforms
products:
  - macOS
  - Python
  - PyTorch
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://blog.trailofbits.com/2024/06/11/exploiting-ml-models-with-pickle-file-attacks-part-1/
  - https://github.com/trailofbits/fickling
rules:
  - title: macOS Suspicious LaunchAgent/Daemon Creation by Python
    description: Detects when a Python process creates or modifies a LaunchAgent or LaunchDaemon plist file.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1543.001
    data_sources:
      - file_event
      - macos
  - title: macOS LaunchAgent/Daemon Plist Modification by Python
    description: Detects when a Python process modifies a LaunchAgent or LaunchDaemon plist file.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1543.001
    data_sources:
      - file_event
      - macos
rules_count: 2
---

This alert focuses on detecting suspicious persistence mechanisms on macOS systems where a Python process is observed creating or modifying LaunchAgent or LaunchDaemon plist files for the first time. Attackers achieving Python code execution, whether through malicious scripts, compromised dependencies, or model file deserialization vulnerabilities such as pickle or PyTorch `__reduce__`, may drop plist files to establish persistence. These LaunchAgents and LaunchDaemons are designed to configure programs to run automatically at login or boot, ensuring the attacker's payload survives reboots and user logouts. This activity is often a strong indicator of compromise because legitimate Python processes rarely need to create persistence mechanisms.

## Attack Chain

1.  Initial Access: The attacker gains initial access to the macOS system through various means, such as exploiting a vulnerability in an application, social engineering, or phishing.
2.  Code Execution: Once inside, the attacker achieves code execution, often leveraging Python through malicious scripts, compromised dependencies (e.g., via pip), or model file deserialization.
3.  Persistence Preparation: The attacker crafts a malicious LaunchAgent or LaunchDaemon plist file.  This file contains configurations to automatically run a specified program at login or boot.
4.  File Creation/Modification: The malicious Python script creates or modifies a plist file in either `/Library/LaunchAgents/`, `~/Library/LaunchAgents/`, or `/Library/LaunchDaemons/`.
5.  Persistence Installation: The system recognizes the new or modified plist file and schedules the specified program to run automatically.
6.  Payload Execution:  At the next login or boot, the system executes the program specified in the plist file, initiating the attacker's payload.
7.  Command and Control: The executed payload establishes a connection to a command-and-control server, allowing the attacker to remotely control the compromised system.

## Impact

Successful exploitation could lead to persistent access to the compromised macOS system, enabling attackers to maintain their foothold even after reboots or user logouts. This can lead to data theft, installation of malware, or further lateral movement within the network. The impact extends to potential data breaches, system compromise, and reputational damage. While the specific number of victims is unknown, the threat affects any macOS system susceptible to malicious Python scripts or compromised dependencies.

## Recommendation

*   Enable Sysmon process-creation and file-creation logging to capture the events required for the rules below (references "process_creation" and "file_event" log sources).
*   Deploy the Sigma rule "macOS Suspicious LaunchAgent/Daemon Creation by Python" to your SIEM and tune for your environment to detect the behavior (references the Sigma rule).
*   Investigate any persistence events involving Python creating LaunchDaemons by reviewing persistence event fields such as `Persistence.runatload`, `Persistence.keepalive`, `Persistence.args`, `Persistence.path` to understand the plist configuration.
