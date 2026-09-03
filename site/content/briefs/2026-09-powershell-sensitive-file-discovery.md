---
title: PowerShell Sensitive File Discovery Technique
slug: 2026-09-powershell-sensitive-file-discovery
description: Adversaries utilize PowerShell commands to recursively search for sensitive file extensions such as .pass and .kdbx to identify credentials or keys stored on disk.
date: "2026-09-03T13:41:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - credential-access
  - powershell
  - windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Adversaries enumerate sensitive files
    confidence_band: high
rules:
  - title: Detect Sensitive File Discovery via PowerShell
    description: Detects the use of PowerShell cmdlets to recursively search for sensitive file extensions such as .pass, .kdbx, or .kdb
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
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
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints
      owner: IT Operations
      due: 48h
      evidence: Required for visibility into PowerShell script execution
  hunt_leads:
    - lead: Search for high-frequency use of recursive search flags in PowerShell logs
      technique_id: T1083
      data_needed:
        - PowerShell Operational Logs (Event 4104)
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Standard adversary reconnaissance behavior
  mitigation_plan:
    - priority: medium
      action: Implement strict access controls on directories containing sensitive credential files
      owner: Security Architecture
      addresses: Discovery of credentials
      evidence: Limiting read access mitigates impact of discovery
---

This technique involves the use of PowerShell cmdlets to perform recursive directory searches specifically targeting sensitive file extensions associated with password managers and credential stores. Adversaries often execute these commands post-compromise to locate, exfiltrate, or harvest credentials necessary for privilege escalation or lateral movement. By leveraging cmdlets such as Get-ChildItem with recursion enabled, attackers can efficiently identify high-value targets across diverse directory structures on a compromised Windows host. Detection of this activity relies on monitoring PowerShell Script Block Logging, as these commands are frequently executed within volatile memory or via one-liners that bypass traditional file-system logging.

## Attack Chain

1. Initial access is established through spearphishing or exploit delivery on the target system.
2. The attacker gains execution of a PowerShell instance or interactive shell.
3. The attacker identifies the current user context and file system structure.
4. The attacker executes a recursive search command (e.g., Get-ChildItem -Recurse) targeting specific patterns like ".kdbx" or ".pass".
5. The search identifies the absolute path to credential-related files on the disk.
6. The attacker reads or exfiltrates the discovered sensitive files to a C2-controlled endpoint.

## Impact

Successful discovery of sensitive files can lead to the compromise of password databases and plain-text credential files, significantly increasing the risk of full account takeover, lateral movement across the network, and long-term persistence through harvested authentication tokens.

## Recommendation

1. Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints to ensure the visibility of script execution.
2. Deploy the provided Sigma rule to detect recursive file searches targeting known credential file extensions.
3. Perform threat hunting for common PowerShell enumeration patterns and investigate high-frequency recursive search activity from unauthorized user accounts.
