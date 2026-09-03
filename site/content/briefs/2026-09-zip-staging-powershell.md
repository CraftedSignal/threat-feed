---
title: PowerShell Data Staging via Compress-Archive
slug: 2026-09-zip-staging-powershell
description: Adversaries frequently use the PowerShell Compress-Archive cmdlet to stage sensitive data for exfiltration within common temporary directories, a technique used to consolidate and obfuscate collected information.
date: "2026-09-03T13:43:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - data-collection
  - powershell
  - staging
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1074
    technique_name: Data Staged
    evidence: An adversary might compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network.
    confidence_band: high
rules:
  - title: Detect Suspicious PowerShell Archive Creation in Temp Directories
    description: Detects the use of Compress-Archive to stage data into common temporary locations used by attackers
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1074.001
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule for PowerShell archive monitoring
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific cmdlet patterns for detection
  hunt_leads:
    - lead: Search for non-standard process creation of .zip or .rar files in %TEMP% folders
      technique_id: T1074.001
      data_needed:
        - Endpoint file creation events (Sysmon ID 11)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Staging in temp folders is a documented post-exploitation behavior
---

Adversaries often utilize native administrative tools such as PowerShell to stage collected data prior to unauthorized exfiltration. A common tactic involves identifying sensitive files or directories and compressing them using the Compress-Archive cmdlet. By directing the output of these compression operations to standard temporary locations like %TEMP%, AppData\Local\Temp, or C:\Windows\Temp, attackers attempt to blend in with legitimate system activities or transient application data. This staging process is a critical precursor to exfiltration, as it minimizes the total volume of data, enables the use of archiving formats for easier transport, and can potentially bypass basic inspection mechanisms that monitor for individual file transfers rather than consolidated archives.

## Attack Chain

1. An attacker identifies sensitive directories containing user data or configuration files on a compromised host.
2. The attacker executes a PowerShell script, often embedded within a malicious payload or run interactively via a remote shell.
3. The script invokes the Compress-Archive cmdlet to recursively bundle the targeted files into a single archive file (e.g., .zip).
4. The archive is written to a temporary directory such as $env:TEMP or C:\Windows\Temp to avoid immediate detection in user-monitored folders.
5. The attacker may then perform obfuscation, such as renaming the archive extension, to bypass simple file-type filtering.
6. The final archive is staged and prepared for exfiltration to an attacker-controlled C2 server or cloud storage bucket.

## Impact

Successful staging enables efficient exfiltration of sensitive organizational data, increasing the risk of data breaches, intellectual property theft, and exposure of PII. While this technique is a component of the collection phase, its prevalence in ransomware and espionage campaigns makes it a high-value indicator of malicious intent when observed in non-administrative contexts.

## Recommendation

Prioritize the deployment of script block logging to monitor for suspicious command execution.
- Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints to capture the full command context, including the parameters used with Compress-Archive.
- Implement the provided Sigma rule in your SIEM to trigger alerts when Compress-Archive is directed to sensitive temporary paths.
- Monitor for the creation of archive files in temporary directories, specifically flagging files with high entropy or those created by non-standard parent processes.
