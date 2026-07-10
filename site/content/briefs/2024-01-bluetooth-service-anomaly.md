---
title: Suspicious Bluetooth Service Installation from Uncommon Location
slug: 2024-01-bluetooth-service-anomaly
description: The creation of a Windows service named 'BluetoothService' with a binary path in user-writable directories, such as %AppData%, indicates potential malware persistence, as seen in the Lotus Blossom Chrysalis backdoor campaign.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Lotus Blossom
tags:
  - persistence
  - defense-evasion
  - windows
  - anomaly
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
references:
  - https://attack.mitre.org/techniques/T1543/003/
  - https://attack.mitre.org/techniques/T1036/
  - https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
rules:
  - title: Detect Bluetooth Service Installed From Uncommon Location
    description: Detects the creation of a Windows service named 'BluetoothService' with a binary path in user-writable directories, indicating potential malware persistence.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1036
      - T1543.003
    data_sources:
      - process_creation
      - windows
  - title: Detect Bluetooth Service Registry Modification
    description: Detects registry modifications related to the 'BluetoothService' service pointing to uncommon locations
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1543.003
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

This threat brief focuses on the anomalous installation of a Windows service named "BluetoothService" from user-writable directories. The Lotus Blossom group used this technique in their Chrysalis backdoor campaign, creating a service that pointed to a malicious binary disguised as the Bitdefender Submission Wizard, located within a hidden AppData directory. This method bypasses standard security measures by mimicking legitimate service installation procedures but placing the malicious service executable in an unexpected location. Legitimate Bluetooth services in Windows are system services with binaries located in System32, making user-directory installations highly suspicious. Monitoring for this activity can help identify potential malware persistence mechanisms. This technique is used for persistence and defense evasion.

## Attack Chain

1.  The attacker gains initial access to the system (potentially through phishing or exploiting a vulnerability).
2.  The attacker drops a malicious executable, masquerading as a legitimate application (e.g., renaming a binary to resemble a Bitdefender tool).
3.  The attacker creates a new Windows service named "BluetoothService" (or "Bluetooth Service").
4.  The "ImagePath" of this service is set to point to the malicious executable located in a user-writable directory (e.g., %AppData%, %ProgramData%, %Temp%, or a user-specific Bluetooth folder).
5.  The service is configured to start automatically, ensuring persistence across reboots.
6.  When the system starts, the malicious "BluetoothService" executes the attacker's code.
7.  The attacker leverages the service to establish a backdoor for remote access and control.
8.  The attacker performs further malicious activities, such as data exfiltration or lateral movement.

## Impact

Successful exploitation allows attackers to establish persistence on the compromised system, enabling them to maintain unauthorized access even after reboots. This can lead to data theft, system compromise, and further propagation of the attack within the network. The Lotus Blossom group has historically targeted organizations in the aerospace, defense, and high-tech sectors, and similar campaigns could result in significant intellectual property loss and reputational damage.

## Recommendation

*   Monitor Windows Event Log (Event ID 7045) for service creation events, focusing on services named "BluetoothService" or "Bluetooth Service" (data_source).
*   Implement the provided Sigma rule to detect the creation of "BluetoothService" with an "ImagePath" pointing to user-writable directories (%AppData%, %ProgramData%, %Temp%, %Users%\*\Bluetooth) (rules).
*   Investigate any instances of "BluetoothService" being created from unusual locations, comparing the binary against known good software (rules).
*   Review and harden endpoint security configurations to prevent unauthorized service creation in user-writable directories (T1543.003).
*   Educate users about the risks of running executables from untrusted sources and the dangers of social engineering tactics (T1036).
