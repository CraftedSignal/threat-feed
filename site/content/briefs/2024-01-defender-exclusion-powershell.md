---
title: Windows Defender Exclusions Added via PowerShell
slug: 2024-01-defender-exclusion-powershell
description: Adversaries may attempt to bypass Windows Defender's capabilities by using PowerShell to add exclusions for folders or processes, and this activity can be detected by monitoring PowerShell command lines that use `Add-MpPreference` or `Set-MpPreference` with exclusion parameters.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - powershell
  - windows
vendors:
  - Microsoft
  - CrowdStrike
  - SentinelOne
  - Elastic
products:
  - Microsoft Defender XDR
  - Elastic Defend
  - CrowdStrike
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.bitdefender.com/files/News/CaseStudies/study/400/Bitdefender-PR-Whitepaper-MosaicLoader-creat5540-en-EN.pdf
  - https://www.elastic.co/security-labs/elastic-security-uncovers-blister-malware-campaign
  - https://www.elastic.co/security-labs/operation-bleeding-bear
  - https://www.elastic.co/security-labs/invisible-miners-unveiling-ghostengine
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_defender_exclusion_via_powershell.toml
rules:
  - title: Windows Defender Exclusion Added via PowerShell
    description: Detects the use of PowerShell to add Windows Defender exclusions.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious PowerShell MpPreference Modification
    description: Detects suspicious modifications to MpPreference settings via PowerShell, excluding legitimate paths.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may attempt to evade detection by modifying Windows Defender's configuration to exclude specific files, folders, or processes from scanning. This is often achieved by using PowerShell commands to add exclusions. The tactic allows malware to operate without being detected by the built-in antivirus solution. Observed as early as 2018 with Trickbot disabling Windows Defender, this technique remains relevant today. This activity can be performed using `Add-MpPreference` or `Set-MpPreference` commands in PowerShell, specifying exclusions by path or process name. Detecting these modifications is critical for maintaining the integrity of endpoint security. The scope of targeting ranges from individual workstations to entire networks.

## Attack Chain

1.  The attacker gains initial access to the system via an undisclosed method.
2.  The attacker executes PowerShell with administrative privileges.
3.  The attacker uses the `Add-MpPreference` or `Set-MpPreference` cmdlet to add an exclusion.
4.  The exclusion specifies a file path, folder, or process that should be ignored by Windows Defender.
5.  Windows Defender is reconfigured to ignore the specified item.
6.  The attacker deploys or executes malware in the excluded location.
7.  The malware operates without interference from Windows Defender.
8.  The attacker achieves their final objective, such as data theft or lateral movement.

## Impact

Successful exploitation allows attackers to operate undetected on compromised systems, leading to potential data breaches, lateral movement within the network, and deployment of ransomware. While the exact number of victims is unknown, this technique is widely used by various threat actors, impacting organizations across various sectors. The lack of detection can lead to prolonged periods of compromise, increasing the potential damage.

## Recommendation

*   Deploy the Sigma rule "Windows Defender Exclusions Added via PowerShell" to your SIEM to detect suspicious PowerShell commands used to add exclusions.
*   Enable Sysmon process creation logging with command line auditing to capture the necessary event data for the Sigma rule.
*   Regularly review Windows Defender exclusion lists to identify any unauthorized or suspicious entries.
*   Investigate any PowerShell process that uses `Add-MpPreference` or `Set-MpPreference` with exclusion parameters, as identified by the provided Sigma rule.
*   Monitor for processes and file modifications within excluded directories.
*   Configure alerts to notify security teams when new Windows Defender exclusions are added.
