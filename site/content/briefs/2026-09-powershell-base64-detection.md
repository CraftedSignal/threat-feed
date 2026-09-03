---
title: Detection of PowerShell Base64 Decoding Techniques
slug: 2026-09-powershell-base64-detection
description: This brief documents the use of the 'FromBase64String' method within PowerShell command lines, a common technique for obfuscating malicious payloads to bypass signature-based detection.
date: "2026-09-03T12:40:46Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - stealth
  - obfuscation
  - powershell
  - detection-engineering
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: The rule detects the use of the FromBase64String function, which is used to decode a base64 encoded string to hide malicious payloads.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: PowerShell
    evidence: The rule targets PowerShell process creation command lines containing specific decoding functions.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_powershell_frombase64string.yml
  - https://gist.github.com/Neo23x0/6af876ee72b51676c82a2db8d2cd3639
rules:
  - title: Detect PowerShell FromBase64String Usage
    description: Detects usage of the 'FromBase64String' function in the command line, which is often used to decode base64-encoded obfuscated PowerShell commands.
    platform: sigma
    severity: high
    tactics:
      - execution
      - stealth
    techniques:
      - T1027
      - T1059.001
      - T1140
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to the SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source provided the logic for detecting base64 decoding in PowerShell.
  hunt_leads:
    - lead: Search for instances of 'FromBase64String' in process execution logs.
      technique_id: T1027
      data_needed:
        - Command line arguments from endpoint logs.
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Technique is a common indicator of obfuscated malicious scripts.
---

Attackers frequently utilize Base64 encoding to obfuscate malicious PowerShell scripts, command-and-control beacons, and payloads. By encoding scripts, adversaries attempt to evade static analysis and security signatures that monitor for specific keywords or malicious patterns within a command line. A common method to execute these encoded commands involves the use of the .NET 'FromBase64String' function, which decodes the obfuscated input before execution. This technique is pervasive across various stages of an attack, including initial staging and lateral movement. Defenders should monitor for the presence of '::FromBase64String(' within process execution telemetry to identify potentially obfuscated PowerShell activity, as this is a high-signal indicator of defensive evasion despite the existence of some legitimate administrative script usage.

## Impact

Successful exploitation of obfuscation techniques allows attackers to bypass baseline security monitoring, facilitating the delivery of secondary payloads, credential harvesting, or unauthorized system access while remaining undetected by simple keyword-based defensive rules.

## Recommendation

Deploy the Sigma rule below to detect potentially malicious PowerShell activity. Prioritize alerting on executions from non-administrative contexts. Review existing automation and deployment scripts that may trigger this rule to reduce false positives through inclusion of authorized process paths.
