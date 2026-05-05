---
title: MpCmdRun Execution with RemoveDefinitions Argument
slug: 2024-01-mpcmdrun-removedefinitions
description: The execution of MpCmdRun.exe with the '-RemoveDefinitions' argument, used to remove definitions from the Windows Malware Protection Engine, can indicate potential malware activity or attempts to bypass security measures.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - endpoint
  - mpcmdrun
  - malware
vendors:
  - Microsoft
  - Splunk
products:
  - Windows Malware Protection Engine
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
references:
  - https://cert.gov.ua/article/6284730
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_mpcmdrun_removedefinitions_execution.yml
rules:
  - title: MpCmdRun RemoveDefinitions Execution
    description: Detects the execution of MpCmdRun.exe with the -RemoveDefinitions argument, which can be used to remove definitions from the Windows Malware Protection Engine.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Parent Process of MpCmdRun
    description: Detects MpCmdRun.exe being executed by a suspicious parent process.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The threat involves the use of MpCmdRun.exe, the command-line interface for Windows Defender, with the `-RemoveDefinitions` argument. This command is designed to remove existing malware definitions from the Windows Malware Protection Engine. While legitimate use cases exist, its execution can also be indicative of malicious activity aimed at disabling or weakening endpoint security controls. An attacker or malware may use this command to bypass detection after gaining initial access. This technique is particularly concerning because it can leave systems vulnerable to known threats by deleting the corresponding definitions.

## Attack Chain

1. Initial Access: The attacker gains initial access to the system, possibly through phishing, exploitation of a vulnerability, or compromised credentials.
2. Privilege Escalation: The attacker escalates privileges to execute commands with administrative rights, necessary to manipulate Windows Defender.
3. Defense Evasion: The attacker executes `MpCmdRun.exe` with the `-RemoveDefinitions` argument.
4. Definition Removal: Windows Defender removes the existing malware definitions, weakening the system's ability to detect and prevent known threats.
5. Malware Deployment: The attacker deploys malware or performs malicious activities, now with a reduced chance of being detected by Windows Defender.
6. Lateral Movement: The attacker uses the compromised system to move laterally within the network, infecting other machines.
7. Data Exfiltration/Ransomware Deployment: The attacker exfiltrates sensitive data or deploys ransomware, leveraging the weakened security posture of the compromised systems.

## Impact

Successful execution of this attack can severely compromise endpoint security. By removing malware definitions, the attacker effectively blinds Windows Defender to known threats. This can lead to successful malware infections, data breaches, ransomware deployment, and overall system instability. If widely deployed across an organization, the impact could affect hundreds or thousands of endpoints, causing significant financial and operational damage.

## Recommendation

*   Deploy the Sigma rule `MpCmdRun RemoveDefinitions Execution` to your SIEM and tune for your environment to detect the execution of `MpCmdRun.exe` with the `-RemoveDefinitions` argument.
*   Investigate any instances of `MpCmdRun.exe` executing with the `-RemoveDefinitions` argument to determine if the behavior is legitimate or malicious, based on the `references` link to Ukraine CERT advisory.
*   Implement strict access controls to limit the ability to execute `MpCmdRun.exe` and other security-related tools.
*   Monitor process execution logs (Sysmon EventID 1, Windows Event Log Security 4688, CrowdStrike ProcessRollup2) for unusual activity related to Windows Defender and other security software.
