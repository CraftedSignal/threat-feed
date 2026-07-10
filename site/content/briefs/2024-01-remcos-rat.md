---
title: Remcos RAT Activity Detection
slug: 2024-01-remcos-rat
description: This brief outlines detection strategies for Remcos RAT activity, focusing on file and registry artifacts indicative of installation, persistence, and cleanup on compromised Windows systems.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remcos
  - rat
  - windows
  - malware
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1219
    technique_name: Remote Access Tools
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://any.run/malware-trends/remcos
  - https://attack.mitre.org/software/S0332/
  - https://www.elastic.co/security-labs/exploring-the-ref2731-intrusion-set
rules:
  - title: Detect Remcos Logs.dat Creation
    description: Detects the creation of the logs.dat file associated with Remcos RAT in the user's AppData\Roaming directory.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - file_event
      - windows
  - title: Detect Remcos Registry Run Key Persistence
    description: Detects the creation or modification of Remcos-related registry keys in the Run key for persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Remcos Temporary File Deletion
    description: Detects the deletion of temporary files associated with Remcos RAT installation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.004
    data_sources:
      - file_event
      - windows
rules_count: 3
---

Remcos is a commercially available Remote Access Trojan (RAT) that is often abused by threat actors for malicious purposes. It allows attackers to remotely control compromised systems, steal sensitive data, and perform other malicious activities. This brief focuses on detecting Remcos activity through identifying specific file and registry artifacts associated with its installation, persistence, and cleanup processes. This includes the detection of log files, registry keys related to persistence, and temporary file deletions indicative of installation cleanup. Monitoring for these activities can help security teams identify and respond to Remcos infections on Windows systems. The techniques described here are derived from observed Remcos behavior and threat intelligence reports linking these artifacts to Remcos RAT campaigns.

## Attack Chain

1.  The attacker gains initial access to the system via an unknown method, potentially through social engineering or exploiting a vulnerability (not covered in source).
2.  The Remcos RAT installer is executed, often masquerading as a legitimate file or application.
3.  Remcos creates a log file at `C:\\Users\\*\\AppData\\Roaming\\remcos\\logs.dat` for keystroke and clipboard logging.
4.  To establish persistence, Remcos creates a registry key under `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run` or `HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run` with a name like "Remcos" or "Rmc-??????". The value of this key points to the Remcos executable. Remcos also creates license-related registry keys, under "*\\SOFTWARE\\Remcos-*\\licence", "*\\Software\\Rmc-??????\\licence".
5.  The Remcos RAT connects to its command-and-control (C2) server to receive instructions from the attacker. (Network activity not covered in source).
6.  The attacker leverages Remcos' capabilities to perform various malicious activities, such as stealing credentials, exfiltrating sensitive data, or deploying additional malware (not covered in source).
7.  Remcos deletes temporary files, `?\\Users\\*\\AppData\\Local\\Temp\\TH????.tmp`, used during installation to cover its tracks.
8.  The attacker maintains persistent remote access to the compromised system using the established Remcos RAT connection.

## Impact

A successful Remcos infection can lead to a wide range of negative impacts, including data theft, financial loss, reputational damage, and disruption of business operations. The attacker gains complete control over the compromised system, allowing them to steal sensitive information, install additional malware, or use the system as a foothold for further attacks within the network. Remcos is often used in targeted attacks against businesses and organizations, resulting in significant financial and operational damage.

## Recommendation

*   Deploy the provided Sigma rules to detect Remcos file and registry artifacts (Sigma rules below).
*   Enable Sysmon file creation, deletion, and registry modification logging on Windows endpoints to provide the necessary data for detection (Sysmon setup links in original source).
*   Investigate any alerts generated by the Sigma rules to determine the extent of the Remcos infection and take appropriate remediation steps. Focus on correlating the process creating the Remcos artifacts.
*   Implement application control policies to prevent the execution of unauthorized applications, including Remcos.
*   Monitor network traffic for connections to known Remcos C2 servers or suspicious network activity originating from infected hosts (requires additional intelligence not in source).
*   Review and harden Windows registry permissions to prevent unauthorized modifications to Run keys and other critical registry locations.
