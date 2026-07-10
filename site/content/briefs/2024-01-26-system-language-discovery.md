---
title: System Language Discovery via Reg.Exe
slug: 2024-01-26-system-language-discovery
description: Adversaries use reg.exe to query system language settings in order to determine the geographic location of victims, customize payloads, or evade detection by avoiding certain locales.
date: "2024-01-26T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - system-language
  - reg.exe
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1614
    technique_name: System Location Discovery
references:
  - https://scythe.io/threat-thursday/threatthursday-darkside-ransomware
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_reg_system_language_discovery.yml
rules:
  - title: System Language Discovery via Reg.Exe CommandLine
    description: Detects the usage of Reg.Exe to query system language settings using command line.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1614.001
    data_sources:
      - process_creation
      - windows
  - title: System Language Discovery via Reg.Exe TargetObject
    description: Detects the usage of Reg.Exe to query system language settings using TargetObject.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1614.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may perform system language discovery to gather information about a compromised host. This information can be used to tailor attacks to specific geographic regions, customize payloads, or avoid targeting systems in certain locales to evade detection. This activity is typically performed using the `reg.exe` utility, a built-in Windows command-line tool for interacting with the registry. While not inherently malicious, the use of `reg.exe` to specifically query language settings (e.g., `Control\Nls\Language`) is a common technique used by threat actors during the reconnaissance phase of an attack. Understanding the target's language and location allows for more effective social engineering, localized malware deployment, and better evasion strategies.

## Attack Chain

1.  The attacker gains initial access to the target system through some method.
2.  The attacker executes `reg.exe` with the `query` parameter to retrieve registry values.
3.  The `CommandLine` includes `query` and `Control\Nls\Language` to specify the target registry key.
4.  `reg.exe` queries the registry for system language settings under `HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language`.
5.  The attacker parses the output of the `reg query` command to extract the installed system languages and regional settings.
6.  The discovered language information is used to customize subsequent stages of the attack, such as delivering localized payloads or avoiding specific regions.
7.  The attacker uses this information to make decisions about further actions on the compromised system, such as tailored payload deployment.

## Impact

Successful system language discovery allows attackers to understand the geographic location of the victim, enabling them to tailor attacks for specific regions. This can lead to more effective social engineering, the deployment of localized malware, or evasion of detection by avoiding systems in certain locales. While this activity itself doesn't cause direct harm, it serves as a crucial step in reconnaissance for a larger attack, potentially leading to data exfiltration, ransomware deployment, or other malicious outcomes.

## Recommendation

*   Deploy the Sigma rule "System Language Discovery via Reg.Exe" to your SIEM to detect suspicious usage of `reg.exe` querying language settings (logsource: process_creation/windows).
*   Investigate any process creations of `reg.exe` with command-line arguments containing both `query` and `Control\Nls\Language`.
*   Monitor process execution for command lines that contain 'reg.exe' and 'Control\Nls\Language' to identify potential reconnaissance activity.
