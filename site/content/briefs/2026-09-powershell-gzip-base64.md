---
title: Detection of Base64-Encoded Gzip Archive Decompression in PowerShell
slug: 2026-09-powershell-gzip-base64
description: This brief documents a detection method for identifying potentially malicious PowerShell scripts that decode base64-encoded Gzip archives to facilitate in-memory code execution.
date: "2026-09-03T13:40:14Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - powershell
  - obfuscation
  - living-off-the-land
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1132
    technique_name: Data Encoding
    evidence: This technique is often used as a method to load malicious content into memory afterward.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_frombase64string_archive.yml
  - https://speakerdeck.com/heirhabarov/hunting-for-powershell-abuse?slide=43
rules:
  - title: Detect Suspicious FromBase64String Usage On Gzip Archive
    description: Detects attempts to decode a base64-encoded Gzip archive within PowerShell scripts, a technique often used to load malicious content into memory.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1132.001
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104)
      owner: IT Operations
      due: 72h
      evidence: Required to capture script content necessary for this detection
  hunt_leads:
    - lead: Search for script blocks containing the combination of 'FromBase64String', 'MemoryStream', and 'H4sI'
      technique_id: T1132.001
      data_needed:
        - PowerShell Event ID 4104
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: This is a known indicator of potential in-memory payload delivery
---

Defenders must monitor for suspicious PowerShell activity involving the decoding of base64-encoded Gzip archives. This technique is frequently utilized by threat actors to obfuscate and deliver malicious payloads directly into memory, bypassing disk-based security controls. The specific pattern identified includes the orchestration of 'FromBase64String' for decoding, 'MemoryStream' for buffer management, and the presence of the 'H4sI' Gzip magic header. This combination suggests an attempt to unpack and execute serialized or compressed shellcode or scripts dynamically. Detecting this behavior requires visibility into PowerShell Script Block Logging, as standard command-line logging often fails to capture the contents of dynamic, memory-resident payloads.

## Impact

Successful exploitation of this technique allows attackers to execute arbitrary, hidden code within the context of a legitimate process. This facilitates stealthy command-and-control communication, credential dumping, or lateral movement, significantly complicating incident response efforts by obscuring the payload footprint on the target system.

## Recommendation

Prioritize visibility into PowerShell activity to detect attempts at in-memory payload delivery.
* Enable PowerShell Script Block Logging (Event ID 4104) across the environment to capture full script content.
* Deploy the Sigma detection rule below to monitor for the specific combination of classes and compression signatures indicative of this technique.
* Tune the detection logic for legitimate administrative scripts that may utilize similar compression utilities for maintenance tasks.
