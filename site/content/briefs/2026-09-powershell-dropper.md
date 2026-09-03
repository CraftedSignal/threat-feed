---
title: Suspicious File Creation via PowerShell
slug: 2026-09-powershell-dropper
description: Detection of PowerShell processes creating executable or script files in non-standard directories, a common behavior used by malware for persistence and staging.
date: "2026-09-03T13:37:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - execution
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: The detection identifies files written by PowerShell commonly used for persistence or payload staging.
    confidence_band: med
rules:
  - title: Potential Binary Or Script Dropper Via PowerShell
    description: Detects PowerShell creating a binary executable or a script file in non-standard paths.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule to test environment.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides detection logic for widespread threat technique.
  hunt_leads:
    - lead: Identify all file creation events originating from PowerShell processes in non-Temp directories.
      technique_id: T1547
      data_needed:
        - Sysmon Event ID 11
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: PowerShell is a primary vector for dropping payloads.
---

This brief addresses the detection of PowerShell processes (powershell.exe, powershell_ise.exe, pwsh.exe) creating files with suspicious extensions, such as .exe, .dll, .bat, or .vbs. Attackers frequently utilize PowerShell to drop secondary payloads, stage malicious scripts, or install persistence mechanisms on compromised Windows systems. While legitimate administrative scripts and software installers may perform similar actions, the monitoring of file creation events in sensitive or unexpected locations is a critical component for identifying malicious dropper activity. Defenders should baseline existing automated scripts within their environment to tune out known-good behavior while focusing on file creation events occurring outside of typical application installation paths.

## Impact

Successful exploitation by a file dropper allows attackers to maintain persistence, execute secondary payloads, and facilitate lateral movement or data exfiltration. Failure to monitor these activities can result in the undetected deployment of remote access trojans (RATs), ransomware, or information stealers.

## Recommendation

Deploy the provided Sigma rule to identify unauthorized file writes triggered by PowerShell processes.
Enable Sysmon file_event (Event ID 11) or equivalent EDR telemetry for file creation monitoring.
Tune the detection by identifying and adding legitimate enterprise software deployment paths or internal script repositories to the filter list.
