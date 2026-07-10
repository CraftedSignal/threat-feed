---
title: Detecting Remcos RAT Activity Through File and Registry Traces
slug: 2024-01-03-remcos-rat
description: This brief provides detection strategies for Remcos RAT, focusing on file and registry artifacts indicative of its presence, persistence, and potential cleanup activities on Windows systems, allowing for the identification and remediation of compromised hosts.
date: "2024-01-03T16:27:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remcos
  - rat
  - trojan
  - windows
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
iocs:
  - type: file
    value: ?:\Users\*\AppData\Roaming\remcos\logs.dat
  - type: registry
    value: '*\Windows\CurrentVersion\Run\Remcos'
  - type: registry
    value: '*\Windows\CurrentVersion\Run\Rmc-???????'
  - type: registry
    value: '*\SOFTWARE\Remcos-*\licence'
  - type: registry
    value: '*\Software\Rmc-??????\licence'
  - type: file
    value: ?:\Users\*\AppData\Local\Temp\TH????.tmp
ioc_counts:
  file: 2
  registry: 4
rules:
  - title: Detect Remcos RAT Registry Run Key Persistence
    description: Detects the creation or modification of Remcos RAT related registry Run keys for persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Remcos RAT Log File Creation
    description: Detects the creation of Remcos RAT log files in the AppData\Roaming directory.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1219
    data_sources:
      - file_event
      - windows
  - title: Detect Remcos RAT Temporary File Deletion
    description: Detects deletion of temporary files associated with Remcos RAT.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1070.004
    data_sources:
      - file_event
      - windows
rules_count: 3
---

Remcos is a Remote Access Trojan (RAT) that allows threat actors to remotely control compromised Windows systems. This brief focuses on identifying Remcos activity through its distinctive file and registry traces, providing detection engineers with actionable intelligence. The observed indicators include the presence of "logs.dat" files in the user's AppData\\Roaming directory, temporary file deletion patterns in the Local\\Temp directory, and specific registry keys related to persistence. This activity is important because Remcos provides extensive remote control capabilities to attackers, including keylogging, screen capture, and file exfiltration, ultimately leading to data theft, system compromise, and potential lateral movement within the network. Understanding these indicators enables defenders to proactively identify and respond to Remcos infections before significant damage occurs. The signatures used by the RAT when creating registry keys include "Remcos", "Rmc-??????", and "licence".

## Attack Chain

1. Initial access is gained through an unknown vector (e.g., malicious email attachment, drive-by download).
2. The Remcos RAT executable is deployed to the compromised system, often placed in a user's AppData folder.
3. The RAT establishes persistence using registry Run keys, such as `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Remcos` or similar variations.
4. Remcos logs user activity, including keystrokes and clipboard data, storing this information in `logs.dat` within the `AppData\Roaming\remcos` directory.
5. The RAT establishes a command and control (C2) connection to an external server, enabling remote access and control by the attacker (Note: C2 activity details not present in source).
6. To evade detection, the attacker may attempt to remove traces of the initial infection by deleting temporary files created during the installation process (e.g., `TH????.tmp` files in the `Local\Temp` directory).
7. The attacker can then use these tools for exfiltration.

## Impact

A successful Remcos infection can lead to significant data loss, system compromise, and financial damage. Attackers can use the RAT to steal sensitive information, such as credentials, financial data, and intellectual property. The compromised system can also be used as a launchpad for further attacks within the network, potentially leading to a widespread breach. The number of victims and the scale of damage depend on the attacker's objectives and the security posture of the targeted organization.

## Recommendation

*   Monitor file creation and deletion events for the creation of `?:\Users\*\AppData\Roaming\remcos\logs.dat` and deletion of `?:\Users\*\AppData\Local\Temp\TH????.tmp` files using file monitoring tools like Sysmon (Event ID 11 and 23), as described in the setup guide, to detect initial infection and cleanup attempts.
*   Implement the provided Sigma rules to detect Remcos registry persistence mechanisms and file activity, adjusting the thresholds and exclusions based on your environment.
*   Monitor registry modifications for the creation or modification of registry keys under `*\Windows\CurrentVersion\Run\` and `*\SOFTWARE\Remcos-*\` related to Remcos using registry monitoring tools like Sysmon (Event ID 13), as described in the setup guide.
*   Investigate any alerts generated by these rules to determine the scope of the infection and take appropriate remediation steps, as outlined in the provided triage and analysis guide.
