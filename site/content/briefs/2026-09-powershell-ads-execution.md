---
title: PowerShell Script Execution from Alternate Data Streams
slug: 2026-09-powershell-ads-execution
description: Detection of attackers using NTFS Alternate Data Streams (ADS) to hide and execute malicious PowerShell scripts, effectively bypassing simple file-based scanning.
date: "2026-09-03T12:41:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - stealth
  - execution
  - persistence
  - powershell
  - ntfs
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: The technique uses NTFS Alternate Data Streams to hide scripts.
    confidence_band: high
rules:
  - title: Detect PowerShell Script Execution from ADS
    description: Detects PowerShell execution where the script content is retrieved from an NTFS Alternate Data Stream (ADS)
    platform: sigma
    severity: high
    tactics:
      - stealth
    techniques:
      - T1564.004
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
    - action: Deploy Sigma detection rule to SIEM environment
      owner: Detection Engineering
      due: 48h
      evidence: Source provides technical logic for ADS PowerShell execution detection
  hunt_leads:
    - lead: Search for Get-Content -Stream in historical command line logs
      technique_id: T1564.004
      data_needed:
        - Process creation command line telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Technique is a known method for hiding and executing malicious code
  mitigation_plan:
    - priority: medium_term
      action: Enable PowerShell Script Block Logging (Event ID 4104)
      owner: IT Operations
      addresses: Hidden PowerShell execution
      evidence: Provides visibility into script content regardless of obfuscation or storage method
---

This threat brief focuses on the technique of executing PowerShell scripts stored within NTFS Alternate Data Streams (ADS). Adversaries leverage ADS to hide malicious code within seemingly benign files, complicating traditional security auditing and static analysis. By attaching scripts to legitimate files, attackers can persist on a system or stage their payloads in a way that is not immediately visible to users or basic file browsers. When the PowerShell interpreter is called to read the content of these streams, the script is executed in memory. This technique is specifically identified as a method for stealth and persistent execution, often utilized during the post-exploitation phase to execute secondary stages of a compromise.

## Attack Chain

1. The attacker gains initial access to the target host through a separate vector.
2. The attacker uses standard Windows utilities to create a hidden stream attached to an existing file (e.g., `echo [payload] > legitimate.txt:malicious.ps1`).
3. The attacker hides the presence of the ADS by modifying file timestamps or attributes to avoid manual inspection.
4. The attacker triggers execution of the hidden script by spawning a PowerShell process.
5. The PowerShell interpreter executes the `Get-Content` cmdlet with the `-Stream` parameter to read the contents of the hidden ADS.
6. The retrieved content is piped directly into the PowerShell runtime for immediate execution without writing a standalone file to disk.
7. The process executes the malicious payload, such as a reverse shell or information stealer, in the context of the running PowerShell process.

## Impact

Successful execution of scripts from ADS enables attackers to maintain stealthy persistence and execute malicious payloads that evade conventional file-integrity monitoring and signature-based detection. This technique allows for the execution of arbitrary code in memory, facilitating lateral movement, data exfiltration, or the deployment of further ransomware components within an enterprise environment.

## Recommendation

Prioritized actions for detection engineering and security operations:
- Deploy the provided Sigma rule to monitor for suspicious use of `Get-Content` with the `-Stream` parameter in PowerShell command lines.
- Enable PowerShell script block logging to inspect the actual contents of the executed scripts regardless of their storage location.
- Review environments for unusual file metadata patterns or processes interacting with non-standard NTFS streams.
- Focus on monitoring child processes spawned by PowerShell that demonstrate unexpected network or file system activity.
