---
title: Suspicious PowerShell Invoke-WebRequest Usage for File Downloads
slug: 2026-09-powershell-iwr-download
description: This threat brief details the detection of suspicious PowerShell Invoke-WebRequest activity used to download payloads into high-risk, world-writable directories on Windows systems.
date: "2026-09-03T15:37:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - powershell
  - command-and-control
  - detection-engineering
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: The detection rule targets usage of web request cmdlets to download remote files.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_powershell_invoke_webrequest_download.yml
  - https://www.sentinelone.com/blog/living-off-windows-defender-lockbit-ransomware-sideloads-cobalt-strike-through-microsoft-security-tool/
rules:
  - title: Detect Suspicious Invoke-WebRequest Execution
    description: Detects the use of PowerShell web request cmdlets directed at high-risk directories such as Temp, AppData, or Public.
    platform: sigma
    severity: high
    tactics:
      - command-and-control
    techniques:
      - T1105
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule 5e3cc4d8 to monitor PowerShell downloader activity.
      owner: Detection Engineering
      due: 72h
      evidence: Source provides vetted Sigma detection logic.
  mitigation_plan:
    - priority: short_term
      action: Restrict write access to public/temp directories for non-service accounts.
      owner: IT Operations
      addresses: T1105
---

Adversaries frequently abuse built-in Windows administrative utilities, specifically the PowerShell Invoke-WebRequest (and its aliases: iwr, curl, wget), to facilitate the download of second-stage payloads from remote infrastructure. By targeting non-standard, world-writable directories such as Temp, AppData, or the Public user profile, attackers attempt to bypass file integrity monitoring or application control policies. This activity is a known component of various campaigns, including ransomware deployments where adversaries sideload beacons or malware components via living-off-the-land techniques. Monitoring for these specific command-line flags and directory paths is essential for early detection of initial access or post-exploitation stage activities.

## Impact

Successful exploitation of this technique typically precedes full system compromise, malware execution, or sensitive data exfiltration. Adversaries using these tools within common directory structures can effectively camouflage malicious file drops as legitimate system or user activity, potentially delaying detection until post-delivery stages like execution or persistence are established.

## Recommendation

Deploy the provided Sigma rule to monitor for suspicious command-line patterns involving PowerShell web requests directed at high-risk file system locations.

- Enable Sysmon or Windows Event Log (Event ID 4688) process creation logging to populate the required fields for detection.
- Tune the detection to exclude legitimate software installers or administrative scripts that use standardized directory structures for temporary file processing.
- Review internal scripts that automate file retrieval to ensure they use approved organizational infrastructure rather than public/temp directory locations.
