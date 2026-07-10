---
title: PowerShell Script Block Logging Disabled via Registry Modification
slug: 2024-01-disable-powershell-scriptblocklogging
description: Attackers may disable PowerShell Script Block Logging by modifying the registry to evade detection and conceal their activities on the host, detected by monitoring changes to the `EnableScriptBlockLogging` registry value.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - powershell
  - defense-evasion
  - windows
vendors:
  - Microsoft
products:
  - PowerShell
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_disable_posh_scriptblocklogging.toml
  - https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.PowerShell::EnableScriptBlockLogging
rules:
  - title: PowerShell Script Block Logging Disabled - Registry Event
    description: Detects registry changes that disable PowerShell Script Block Logging.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1112
      - T1562.002
    data_sources:
      - registry_set
      - windows
  - title: PowerShell Script Block Logging Disabled - Process Creation with Reg.exe
    description: Detects command lines using reg.exe to disable PowerShell Script Block Logging.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1112
      - T1562.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers frequently disable PowerShell Script Block Logging to reduce the visibility of their actions on a compromised host. By modifying the `EnableScriptBlockLogging` registry value, adversaries can prevent PowerShell scripts from being logged, making it harder for defenders to detect malicious activity. This technique is often employed after initial access and privilege escalation to further obfuscate subsequent actions. The Elastic detection rule "PowerShell Script Block Logging Disabled", updated on 2026/04/07, identifies these registry modifications, focusing on changes to the `EnableScriptBlockLogging` registry value. This defense evasion tactic is crucial to detect as it directly impacts the effectiveness of PowerShell-based security monitoring. The rule aims to identify instances where this setting is disabled by unauthorized processes.

## Attack Chain

1.  Initial Access: An attacker gains initial access to a Windows system, potentially through phishing or exploiting a software vulnerability.
2.  Privilege Escalation: The attacker escalates privileges to obtain the necessary rights to modify the registry. This could involve exploiting a local vulnerability or using stolen credentials.
3.  Identify Target Registry Key: The attacker identifies the registry key responsible for controlling PowerShell Script Block Logging: `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging`.
4.  Modify Registry Value: The attacker modifies the `EnableScriptBlockLogging` registry value to `0` or `0x00000000`, effectively disabling PowerShell Script Block Logging. This is often accomplished using `reg.exe` or PowerShell itself.
5.  Execute Malicious PowerShell Script: With Script Block Logging disabled, the attacker executes a malicious PowerShell script designed to perform actions such as lateral movement, data exfiltration, or deploying ransomware.
6.  Evasion and Persistence: The attacker implements persistence mechanisms to maintain access to the system, potentially modifying other registry keys or creating scheduled tasks.
7.  Lateral Movement: The attacker leverages PowerShell to move laterally to other systems within the network, exploiting trust relationships or vulnerabilities.
8.  Data Exfiltration / Ransomware Deployment: Finally, the attacker achieves their objective, whether it's exfiltrating sensitive data or deploying ransomware across the network.

## Impact

Successful disabling of PowerShell Script Block Logging can severely impair an organization's ability to detect and respond to PowerShell-based attacks. This can lead to prolonged dwell time for attackers, increased damage from data breaches, and widespread ransomware infections. Without proper logging, defenders lose critical visibility into attacker activities, making incident response and forensic analysis significantly more challenging. Disabling logging can affect an entire organization, depending on how widely PowerShell is used for legitimate administration.

## Recommendation

*   Deploy the Sigma rule "PowerShell Script Block Logging Disabled" to your SIEM and tune for your environment to detect malicious registry modifications (rules section).
*   Enable Sysmon process-creation and registry event logging to ensure the Sigma rules have the necessary data to function (logsource).
*   Investigate any alerts generated by the Sigma rule to determine the legitimacy of the registry modification, focusing on the process and user context (rules section).
*   Implement Group Policy to enforce PowerShell Script Block Logging and prevent unauthorized modifications (references).
*   Monitor for repeated attempts to disable Script Block Logging, especially from the same user or originating process, to identify persistent threats (rules section).
