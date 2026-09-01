---
title: Execution via NTFS Alternate Data Streams
slug: 2026-09-execute-ads
description: Adversaries utilize NTFS Alternate Data Streams to hide and execute malicious payloads, evading detection by conventional file analysis tools.
date: "2026-09-01T12:24:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - stealth
  - persistence
  - ads
  - ntfs
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_alternate_data_streams.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1564.004/T1564.004.md
rules:
  - title: Detect Execution from Alternate Data Streams
    description: Detects execution activity associated with NTFS Alternate Data Streams by monitoring suspicious command line patterns from common Windows utilities.
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
  immediate_actions:
    - action: Deploy Sigma rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Rule provides detection for T1564.004
  hunt_leads:
    - lead: Search for process execution command lines containing a colon
      technique_id: T1564.004
      data_needed:
        - Process command line
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source document identifies ADS interaction via colon syntax in command lines
  mitigation_plan:
    - priority: medium
      action: Review and restrict usage of administrative utilities for standard users
      owner: IT Operations
      addresses: T1564.004
      evidence: Technique relies on native binaries to interact with streams
---

Adversaries frequently leverage the Windows New Technology File System (NTFS) feature known as Alternate Data Streams (ADS) to conceal malicious code or configuration data. Because ADS allows files to contain multiple data streams, attackers can hide executables or scripts in non-visible streams attached to legitimate files. This technique effectively bypasses many signature-based security products that only scan the primary data stream of a file. By executing code directly from these streams, threat actors maintain persistence and minimize their forensic footprint. Defenders must monitor process creation events that interact with these streams using common Windows administrative utilities that can be repurposed to write or execute data contained within them.

## Attack Chain

1. Attacker gains initial access to the Windows endpoint.
2. Attacker downloads or stages a malicious payload (e.g., shellcode or script) onto the file system.
3. Attacker uses a system utility (e.g., 'type') to move the payload into an Alternate Data Stream of a legitimate file (e.g., 'file.txt:malware.exe').
4. Attacker uses a second utility or a direct execution call (e.g., 'wmic' or 'powershell') to trigger the execution of the payload stored in the stream.
5. The OS kernel retrieves and executes the data from the specified stream while the file appears benign under standard inspection.
6. The payload runs in memory or spawns a secondary process to establish C2 communication.
7. Attacker achieves command execution and potential persistence without creating new suspicious file objects in the standard file list.

## Impact

Successful exploitation allows for the execution of arbitrary code with stealth, significantly complicating incident response and forensic analysis. This technique has been observed in various APT campaigns and malware families to bypass endpoint security controls that focus on primary file data, leading to unauthorized access and persistence in targeted environments.

## Recommendation

Prioritize the deployment of the provided Sigma rule to detect the creation and access of Alternate Data Streams using standard utilities. Enable Sysmon process-creation logging and focus on command lines that include the colon character (':') to identify suspicious stream interactions. Proactively hunt for process command lines that deviate from standard usage, specifically those using 'type', 'makecab', 'reg', 'regedit', or 'esentutl' in combination with data streams.
