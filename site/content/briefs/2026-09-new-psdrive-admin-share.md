---
title: Detection of Suspicious New-PSDrive Mapping to Administrative Shares
slug: 2026-09-new-psdrive-admin-share
description: Adversaries may use the New-PSDrive PowerShell cmdlet to map administrative network shares via SMB for lateral movement and remote file interaction.
date: "2026-09-03T13:42:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - powershell
  - smb
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: Adversaries may use to interact with a remote network share using Server Message Block (SMB).
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_susp_new_psdrive.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1021.002/T1021.002.md#atomic-test-2---map-admin-share-powershell
  - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-psdrive?view=powershell-7.2
rules:
  - title: Detect Suspicious New-PSDrive to Admin Share
    description: Detects the use of New-PSDrive to map network administrative shares, which is a technique used for lateral movement.
    platform: sigma
    severity: medium
    tactics:
      - lateral-movement
    techniques:
      - T1021.002
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints.
      owner: IT Operations
      due: 48h
      evidence: Required for visibility into this TTP.
  hunt_leads:
    - lead: Search for historical occurrences of New-PSDrive combined with UNC paths ending in $.
      technique_id: T1021.002
      data_needed:
        - PowerShell Event ID 4104
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: This is a known lateral movement TTP.
  mitigation_plan:
    - priority: medium
      action: Restrict SMB access and administrative share permissions to authorized jump servers only.
      owner: IT Operations
      addresses: T1021.002
      evidence: Reduces the attack surface for SMB-based lateral movement.
---

Adversaries often leverage PowerShell to facilitate lateral movement within compromised environments. A common technique involves the use of the New-PSDrive cmdlet to map remote network shares, specifically administrative shares (e.g., C$, ADMIN$), using the Server Message Block (SMB) protocol. By creating a temporary drive mapping, an attacker can interact with remote file systems, execute tools, or exfiltrate sensitive data as the currently logged-on user. This activity is frequently observed during the post-exploitation phase of an intrusion, where attackers attempt to pivot from a single compromised host to other systems within the network. Defenders should monitor PowerShell Script Block Logging (Event ID 4104) to identify these drive mappings, as they are often indicative of malicious administrative activity.

## Impact

Successful exploitation of this technique allows attackers to move laterally across an environment, bypass local security controls by accessing remote resources, and potentially escalate privileges if the current session has appropriate permissions on the target host.

## Recommendation

Detection engineering teams should focus on identifying unauthorized PowerShell usage of network drive mappings.
- Enable PowerShell Script Block Logging (Event ID 4104) to capture the full command-line context of script execution.
- Deploy the provided Sigma rule to detect the specific pattern of New-PSDrive parameters associated with admin share mapping.
- Investigate any host triggering this rule to determine if the activity is part of an authorized administrative task or unauthorized lateral movement.
