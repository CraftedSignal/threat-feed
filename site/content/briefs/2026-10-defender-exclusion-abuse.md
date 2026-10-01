---
title: Abuse of Microsoft Defender Antivirus Exclusions for Malware Evasion
slug: 2026-10-defender-exclusion-abuse
description: Adversaries leverage legitimate Microsoft Defender Antivirus exclusion settings via PowerShell, WMI, and GPO to bypass real-time scanning and hide malicious payloads from endpoint detection.
date: "2026-10-01T04:21:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - windows
  - living-off-the-land
vendors:
  - Microsoft
products:
  - Windows Defender Antivirus
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Adversaries leveraging Microsoft Defender Antivirus (MDAV) settings to circumvent scans on their malicious binaries.
    confidence_band: high
rules:
  - title: Detect Suspicious Microsoft Defender Exclusion Modification
    description: Detects the addition of Defender exclusions using PowerShell or WMI methods, often indicative of an attacker attempting to hide malicious artifacts.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review current MDAV exclusion policies via Group Policy or CSP to ensure no overly permissive paths exist
      owner: IT Operations
      due: 48h
      evidence: Source document identifies Path and Extension exclusions as the most valuable for attackers.
  hunt_leads:
    - lead: Audit HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions for unexpected paths
      technique_id: T1562.001
      data_needed:
        - Registry event logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Registry modification is a core mechanism for setting exclusions.
---

Adversaries are increasingly exploiting Microsoft Defender Antivirus (MDAV) exclusions to maintain undetected persistence and execute malicious binaries without triggering security alerts. By manipulating exclusion settings, attackers can bypass real-time monitoring, scheduled scans, and on-demand analysis for specific paths, processes, file extensions, or network traffic. 

The technique requires elevated privileges (administrator or higher). Once elevated, attackers interact with the MDAV engine (MsMpEng.exe) through legitimate administrative interfaces, specifically PowerShell's `Set-MpPreference` or `Add-MpPreference` cmdlets, the `MSFT_MpPreference` WMI class, or by pushing Group Policy Objects (GPO) to target systems. These actions update registry keys under `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` or policy-based registry locations. Historical campaigns, including GootKit (2019), WhisperGate (2022), and Muddled Libra (2024), demonstrate that threat actors use these methods to exclude staging directories or entire drives (like C:\) from protection, enabling the unhindered execution of malware.

## Impact

Successful abuse of MDAV exclusions renders endpoint protection ineffective, allowing attackers to deploy and execute ransomware, infostealers, or persistence mechanisms without interference. This evasion technique increases the dwell time of attackers within a network, as traditional signature-based and heuristic detection capabilities are blinded to the excluded content. This remains a significant risk for organizations where administrative privilege hygiene is poor, allowing attackers to easily modify security preferences to suit their campaign objectives.

## Recommendation

- Implement strict Principle of Least Privilege (PoLP) to limit the number of users and processes with the authority to modify Defender preferences.
- Monitor PowerShell and WMI activity for calls to `Set-MpPreference` or `Add-MpPreference` using suspicious parameters like `ExclusionPath`.
- Audit existing Defender exclusions across the fleet to identify unauthorized or broad directory exclusions, such as those targeting the entire C:\ drive.
- Deploy the Sigma rules below to detect unauthorized modifications to Defender settings via PowerShell and WMI.
