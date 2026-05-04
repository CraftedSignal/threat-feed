---
title: PowerShell Script Block Logging Disabled via Registry Modification
slug: 2024-01-09-disable-powershell-scriptblock-logging
description: Attackers may disable PowerShell Script Block Logging by modifying the registry to conceal their activities on the host and evade detection by setting the `EnableScriptBlockLogging` registry value to 0, impacting security monitoring and incident response capabilities.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - powershell
  - registry
vendors:
  - Microsoft
  - Trend Micro
  - N-able
products:
  - Defender XDR
  - Cloud Endpoint
  - AutomationManagerAgent
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.PowerShell::EnableScriptBlockLogging
  - https://attack.mitre.org/techniques/T1112/
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/002/
rules:
  - title: PowerShell Script Block Logging Disabled
    description: Detects registry changes that disable PowerShell Script Block Logging.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
    data_sources:
      - registry_set
      - windows
  - title: PowerShell Script Block Logging Disabled via PowerShell
    description: Detects PowerShell commands used to disable Script Block Logging via registry modification.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1059.001
      - T1562.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers frequently disable PowerShell Script Block Logging to evade detection and hide malicious activities on compromised systems. By modifying the `EnableScriptBlockLogging` registry value to '0' or '0x00000000', adversaries can significantly reduce the visibility into their PowerShell-based attacks. This technique is particularly effective when followed by script-driven activity, making it harder for security teams to identify and respond to threats. This behavior has been observed across multiple environments, including those utilizing endpoint detection and response solutions such as Elastic Defend, Microsoft Defender XDR, SentinelOne, and CrowdStrike. The rule was last updated on 2026-05-04 and is designed to detect these specific registry modifications.

## Attack Chain

1.  **Initial Access:** An attacker gains initial access to a Windows system, possibly through phishing or exploitation of a vulnerability.
2.  **Privilege Escalation:** The attacker may attempt to escalate privileges to gain necessary permissions to modify the registry.
3.  **Defense Evasion:** The attacker modifies the registry to disable PowerShell Script Block Logging by setting `HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging` to 0 or 0x00000000 using `reg.exe` or PowerShell itself.
4.  **Execution:** The attacker executes malicious PowerShell scripts, leveraging the disabled logging to avoid detection. These scripts may be used for reconnaissance, lateral movement, or data exfiltration.
5.  **Persistence:** The attacker establishes persistence using various techniques, such as creating scheduled tasks or modifying registry keys to ensure continued access to the system.
6.  **Command and Control:** The attacker establishes a command and control channel to communicate with the compromised system and issue further instructions.
7.  **Lateral Movement:** The attacker moves laterally to other systems on the network, compromising additional assets.
8.  **Impact:** The attacker achieves their final objective, such as data theft, ransomware deployment, or disruption of services.

## Impact

Successful disabling of PowerShell Script Block Logging can severely hinder incident response efforts, allowing attackers to operate undetected for extended periods. Organizations may experience data breaches, financial losses, and reputational damage. The impact can be widespread as attackers leverage compromised systems for lateral movement and further exploitation. The loss of PowerShell logging can blind security teams, making it difficult to reconstruct attacker actions and contain the breach.

## Recommendation

*   Deploy the Sigma rule `PowerShell_Script_Block_Logging_Disabled` to your SIEM to detect registry modifications that disable PowerShell Script Block Logging.
*   Monitor registry events for changes to the `EnableScriptBlockLogging` value, focusing on events with `registry.data.strings` set to "0" or "0x00000000" (see rule `PowerShell_Script_Block_Logging_Disabled`).
*   Enable Sysmon registry event logging to capture the necessary data for the Sigma rules to function effectively (see references).
*   Review and harden PowerShell execution policies to prevent unauthorized script execution (related to tactic TA0005).
*   Implement strict access controls to limit who can modify registry settings related to PowerShell logging (related to tactic TA0005).
