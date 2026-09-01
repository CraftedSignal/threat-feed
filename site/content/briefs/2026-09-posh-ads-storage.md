---
title: Detection of PowerShell Alternate Data Stream File Storage
slug: 2026-09-posh-ads-storage
description: Adversaries utilize PowerShell to store malicious payloads within NTFS Alternate Data Streams (ADS) to evade detection and maintain stealthy persistence.
date: "2026-09-01T12:18:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - stealth
  - powershell
  - ntfs
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: Storing files in Alternate Data Stream (ADS) similar to Astaroth malware.
    confidence_band: high
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.004/T1564.004.md
rules:
  - title: Detect PowerShell Storing File in Alternate Data Stream
    description: Detects PowerShell commands that utilize Start-Process and the redirection operator to write data into NTFS Alternate Data Streams, a technique used for stealthy persistence.
    platform: sigma
    severity: medium
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
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints.
      owner: IT Operations
      due: 72h
      evidence: Source requirement for detection visibility.
  mitigation_plan:
    - priority: medium_term
      action: Restrict non-administrative access to create or modify Alternate Data Streams where possible.
      owner: IT Operations
      addresses: T1564.004
      evidence: Hardening against ADS-based persistence.
---

Adversaries often leverage NTFS Alternate Data Streams (ADS) to conceal malicious scripts or binaries on Windows systems. By storing code in a stream attached to a legitimate file, attackers can bypass traditional signature-based security tools that may only scan the primary data stream. This technique was notably employed by the Astaroth malware to maintain a low profile. Monitoring for PowerShell commands that redirect output into specific file streams using the 'comspec' environment variable is critical for identifying this behavior. Defenders should prioritize visibility into PowerShell Script Block Logging, as this is the primary mechanism for capturing the execution of these stream-redirection commands in a post-exploitation or persistence context.

## Attack Chain

1. Attacker gains initial access to the Windows host via spearphishing or exploit.
2. PowerShell is invoked to stage a malicious payload on the local filesystem.
3. Attacker identifies a legitimate host file to serve as a carrier for the ADS payload.
4. The command sequence is structured using Start-Process, the comspec environment variable, and the redirection operator (>).
5. The malicious file content is written into the Alternate Data Stream of the target host file (e.g., target.txt:malicious.exe).
6. Persistence or secondary execution is achieved by invoking the payload directly from the hidden stream.
7. The primary file remains unchanged, appearing benign to standard file system audits.

## Impact

Successful implementation of this technique allows an attacker to hide malicious tools or malware on compromised systems, significantly increasing the difficulty of incident response and forensic analysis. This method facilitates long-term persistence and credential harvesting while avoiding detection by file-integrity monitoring tools that do not specifically account for NTFS streams.

## Recommendation

- Enable PowerShell Script Block Logging (Event ID 4104) across the environment to capture the full command line of executed scripts.
- Deploy the Sigma rule below to detect suspicious redirection patterns targeting ADS.
- Audit high-value systems for the presence of unexpected Alternate Data Streams.
- Investigate any 'Start-Process' execution that attempts to redirect shell output to unconventional file paths or hidden streams.
