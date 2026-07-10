---
title: Suspicious Execution from Mounted Device
slug: 2024-01-suspicious-execution-from-mounted-device
description: This threat brief covers the detection of suspicious executables running from mounted devices, a common tactic used for defense evasion and malware deployment.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - execution
  - mounted-device
vendors:
  - Microsoft
products:
  - Windows Operating System
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_suspicious_execution_from_mounted_device.toml
rules:
  - title: Execution from Removable Drive
    description: Detects execution of programs from removable drives.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
  - title: Execution from Network Share
    description: Detects execution of programs directly from a network share.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Execution from Mounted Device via cmd.exe
    description: Detects execution of programs from mounted devices using cmd.exe, which can be a sign of malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Attackers often leverage mounted devices (e.g., USB drives, network shares) to bypass security controls and execute malicious code. This technique is particularly effective because it can circumvent application whitelisting and other security measures that focus on local drives. The execution of binaries from these locations can indicate malicious activity, such as the deployment of malware, execution of rogue scripts, or unauthorized access to sensitive data. Detecting such executions is crucial for identifying and mitigating potential threats. The focus is on identifying unusual process creation events originating from removable or network drives, which deviate from normal system behavior. This brief provides detection rules to identify this activity.

## Attack Chain

1.  An attacker gains initial access to a system (e.g., via phishing or compromised credentials).
2.  The attacker connects a malicious USB drive or mounts a network share containing malware.
3.  The attacker uses social engineering or exploits autorun features (if enabled) to trigger the execution of a malicious executable on the mounted device.
4.  The malicious executable (e.g., a .exe or .dll file) is launched, bypassing standard application whitelisting policies that may only monitor local drives.
5.  The executed malware establishes persistence, potentially by creating scheduled tasks or modifying registry keys.
6.  The malware performs malicious activities, such as data exfiltration, lateral movement, or ransomware deployment.
7.  The attacker leverages the compromised system to access other resources within the network.

## Impact

Successful execution of malicious code from a mounted device can lead to a wide range of damaging outcomes. This includes data theft, system compromise, ransomware infection, and denial-of-service attacks. Organizations failing to detect this activity risk significant financial losses, reputational damage, and operational disruption. The impact can range from a single compromised workstation to a widespread network breach, depending on the attacker's objectives and the malware's capabilities.
