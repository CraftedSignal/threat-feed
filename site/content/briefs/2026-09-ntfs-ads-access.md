---
title: Detection of NTFS Alternate Data Stream Manipulation via PowerShell
slug: 2026-09-ntfs-ads-access
description: Adversaries utilize NTFS Alternate Data Streams (ADS) to conceal malicious payloads and configuration data on Windows systems by appending information to existing files.
date: "2026-09-03T12:36:14Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - stealth
  - persistence
  - windows
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: Detects writing data into NTFS alternate data streams from powershell.
    confidence_band: high
references:
  - https://web.archive.org/web/20220614030603/http://www.powertheshell.com/ntfsstreams/
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.004/T1564.004.md
rules:
  - title: Detect PowerShell NTFS Alternate Data Stream Access
    description: Detects the creation or modification of NTFS alternate data streams using PowerShell cmdlets Set-Content or Add-Content.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1564.004
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints
      owner: IT Operations
      due: 48h
  hunt_leads:
    - lead: Search for logs containing '-Stream' in PowerShell script blocks
      technique_id: T1564.004
      data_needed:
        - Event ID 4104
      priority: medium
      confidence: medium
      disposition: convert_to_detection
---

NTFS Alternate Data Streams (ADS) are a feature of the Windows New Technology File System (NTFS) that allows data to be attached to a file without changing its size or visibility in standard directory listings. Attackers leverage this capability to hide malware, configuration files, or staging tools from traditional file-based detection mechanisms and manual inspection. By using PowerShell cmdlets such as Set-Content or Add-Content with the -Stream parameter, actors can write arbitrary content into these streams. While ADS has legitimate use cases in Windows, such as storing file metadata or zone identifiers, its abuse for concealment is a common technique for persistence, execution, and data staging. Defenders should monitor PowerShell script block logs for patterns indicating the use of these cmdlets in conjunction with stream targeting.

## Impact

Successful abuse of ADS allows attackers to maintain stealthy persistence and stage malicious payloads on compromised systems. This technique hinders forensic analysis and evades standard file integrity monitoring tools, potentially leading to unauthorized code execution, credential harvesting, or exfiltration of sensitive data that is hidden within legitimate host files.

## Recommendation

Prioritize visibility into PowerShell execution by ensuring Script Block Logging (Event ID 4104) is enabled and forwarded to the SIEM.

- Deploy the provided Sigma rule to detect PowerShell-based ADS manipulation.
- Monitor for unauthorized modification of critical system files where ADS may be used to inject malicious code.
- Investigate alerts triggered by non-standard processes using the -Stream parameter, particularly when associated with common system utilities or user-writable directories.
