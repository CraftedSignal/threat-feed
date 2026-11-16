---
brief_id: brief-2026-11-16-cmd-encoded-sequences
event_id: brief-2026-11-16-cmd-encoded-sequences
revision: 1
activity_at: "2026-11-16T21:28:01Z"
title: Windows Cmd Command Line With Encoded Character Sequences
slug: 2026-11-cmd-encoded-sequences
description: Threat actors, including those leveraging ClickFix payloads, utilize cmd.exe command lines containing long sequences of encoded characters to hide malicious stages for later execution.
date: "2026-11-16T21:28:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  likelihood: likely
qa_status:
  verdict: pass
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027.010
    technique_name: Command Obfuscation
    evidence: The following analytic detects cmd.exe command lines that contain long sequences of encoded characters, such as decimal values (12;70;18;...), hexadecimal values (0x41,0x42,...), HTML entities, or Unicode and octal escapes.
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: Windows Command Shell
    evidence: The following analytic detects cmd.exe command lines that contain long sequences of encoded characters... before launching PowerShell.
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_cmd_command_line_with_encoded_character_sequences.yml
  - https://attack.mitre.org/techniques/T1027/010/
  - https://attack.mitre.org/techniques/T1140/
  - https://attack.mitre.org/techniques/T1059/003/
  - https://www.proofpoint.com/us/blog/threat-insight/security-brief-clickfix-social-engineering-technique-floods-threat-landscape
rules:
  - title: Windows Cmd Command Line With Encoded Character Sequences
    description: Detects cmd.exe command lines that contain long sequences of encoded characters, such as decimal, hexadecimal, HTML entities, or Unicode/octal escapes, often used to hide malicious payloads.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027.010
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

## Overview

The detection identifies cmd.exe command lines containing long sequences of encoded characters, including decimal values, hexadecimal values, HTML entities, Unicode, or octal escapes. This technique is used by loaders, such as ClickFix payloads that retrieve commands via finger, to hide malicious stages as an index list decoded at runtime by cmd.exe using delayed variable expansion.

## Attack Chain

1. A payload, such as a ClickFix lure, utilizes cmd.exe to execute commands.
2. The cmd.exe command line includes long sequences of encoded characters.
3. CMD decodes the character sequences via delayed variable expansion.
4. The resulting command is executed, potentially launching PowerShell to run a download cradle with an AMSI bypass.

## Impact

Successful execution of this technique can result in the execution of hidden payloads, such as download cradles configured to perform an AMSI bypass.

## Recommendation

Implement detection using logs containing process GUID, process name, and parent process, and ensure complete command-line executions are ingested. Normalize data using the Splunk Common Information Model (CIM) and map events to the Processes node of the Endpoint data model. Use the provided regex-based analytic to identify the specified encoded character sequences, and filter results based on parent process or command-line analysis to reduce false positives from legitimate scripts like network scanners or build tools.
