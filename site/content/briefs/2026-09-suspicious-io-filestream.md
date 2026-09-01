---
title: Detection of Direct Volume Access via PowerShell IO.FileStream
slug: 2026-09-suspicious-io-filestream
description: Adversaries may use PowerShell to open a handle to disk volumes via DOS device paths to perform direct, unauthorized file system access or bypass security controls.
date: "2026-09-01T11:06:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - stealth
  - file-access
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1006
    technique_name: Direct Volume Access
    evidence: The activity leverages the \\.\ path to access raw disk volumes, which is a known method for bypassing Windows file access controls.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_iofilestream.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1006/T1006.md
rules:
  - title: Detect Direct Volume Access via PowerShell IO.FileStream
    description: Detects PowerShell scripts that open a handle on a drive volume using the \\. DOS device path specifier to perform direct access.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1070.003
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to environment
      owner: Detection Engineering
      due: 48h
      evidence: Source provides high-fidelity detection pattern for T1006.
  hunt_leads:
    - lead: Search PowerShell logs for raw volume path patterns
      technique_id: T1006
      data_needed:
        - Event ID 4104
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Detection rule logic identifies this behavior.
---

This brief addresses the risk of unauthorized direct disk volume access initiated through PowerShell. Attackers leverage the .NET IO.FileStream class to interact with volume objects using the Windows DOS device path syntax (starting with '\\\\.\\'). By accessing the raw volume handle, threat actors can bypass standard Windows API restrictions, potentially reading sensitive data or examining raw file system structures. This technique is often associated with efforts to circumvent file-level security, perform stealthy data exfiltration, or inspect disk sectors for forensic artifacts. Defenders must monitor PowerShell Script Block Logging for the instantiation of IO.FileStream objects targeting raw device paths to identify potential administrative abuse or malicious post-exploitation activity.

## Impact

Successful exploitation allows an adversary to read raw data from disk volumes, potentially bypassing file system permissions, auditing, and access control lists (ACLs). This can lead to the exposure of sensitive files, configuration data, or security logs that are otherwise protected from standard user-mode access.

## Recommendation

* Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints to capture the full command syntax necessary for detection.
* Deploy the provided Sigma rule to identify instances where the IO.FileStream class is used in conjunction with device path identifiers.
* Investigate detected activity to determine if it stems from administrative scripts or unauthorized post-exploitation tools.
