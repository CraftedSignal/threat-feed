---
title: Windows Peripheral Device Discovery via fsutil
slug: 2024-01-09-peripheral-discovery
description: Adversaries use the Windows file system utility `fsutil.exe` with the `fsinfo drives` argument to enumerate attached peripheral devices for reconnaissance and situational awareness after gaining initial access.
date: "2024-01-09T14:22:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - windows
  - fsutil
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1120
    technique_name: Peripheral Device Discovery
references:
  - https://attack.mitre.org/techniques/T1120/
rules:
  - title: Detect Peripheral Device Discovery via fsutil.exe
    description: Detects the execution of fsutil.exe to enumerate drives connected to a Windows system.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1120
    data_sources:
      - process_creation
      - windows
  - title: Detect Peripheral Device Discovery via fsutil.exe (Original Filename)
    description: Detects the execution of fsutil.exe renamed with `fsinfo drives` arguments connected to a Windows system.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1120
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

After gaining initial access to a Windows system, attackers often perform discovery activities to understand the environment and identify valuable targets. One technique involves using the built-in `fsutil.exe` utility to gather information about peripheral devices connected to the system. This includes identifying secondary drives used for backups, mapped network drives, and removable media. This information can help attackers locate sensitive data, identify backup locations, or find removable drives for data exfiltration. This activity is not inherently malicious but, when coupled with other suspicious behaviors, it indicates potential post-compromise reconnaissance activity. This activity has been observed across various sectors and is a common tactic used by both opportunistic and advanced threat actors.

## Attack Chain

1. Initial Access: The attacker gains initial access to a Windows system through methods such as phishing, exploiting vulnerabilities, or using compromised credentials.
2. Execution: The attacker executes `fsutil.exe` with the `fsinfo drives` arguments via command line or other execution methods.
3. Discovery: `fsutil.exe` queries the operating system for information about connected peripheral devices.
4. Data Collection: The attacker parses the output of the `fsutil fsinfo drives` command to identify attached drives, including USB drives, network shares, and other removable media.
5. Target Identification: The attacker uses the information gathered to identify potential targets, such as backup drives, network shares containing sensitive data, or removable media for later exfiltration.
6. Lateral Movement (Optional): Based on discovered information, the attacker may attempt to move laterally to other systems or network shares.
7. Data Exfiltration (Optional): If sensitive data is located on the discovered drives, the attacker may attempt to exfiltrate the data.

## Impact

Successful execution of peripheral device discovery provides attackers with valuable information about the compromised environment, enabling them to identify and target sensitive data, backup locations, or removable media. This can lead to data theft, system compromise, or further lateral movement within the network. While the direct impact of this technique is low, it significantly contributes to the success of subsequent malicious activities.

## Recommendation

*   Enable Sysmon process creation logging to detect the execution of `fsutil.exe` with command-line arguments (see rules below).
*   Monitor Windows Security Event Logs for process creation events related to `fsutil.exe` (Data Source: Windows Security Event Logs).
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
