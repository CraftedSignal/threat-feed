---
title: Detection of Offensive PowerShell Toolkit Execution
slug: 2026-10-powershell-script-block-detection
description: This detection monitors PowerShell Script Block Logging (EventCode 4104) to identify patterns indicative of credential theft, lateral movement, and persistence used by offensive toolkits.
date: "2026-10-05T18:02:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - powershell
  - detection
  - post-exploitation
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The following analytic detects the execution of multiple offensive toolkits and commands by leveraging PowerShell Script Block Logging (EventCode=4104).
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://github.com/PowerShellMafia/PowerSploit
  - https://github.com/PowerShellEmpire/
  - https://github.com/S3cur3Th1sSh1t/PowerSharpPack
rules:
  - title: Detect Known Malicious PowerShell Script Blocks
    description: Detects execution of PowerShell commands containing known malicious strings associated with offensive toolkits via EventCode 4104
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
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
    - action: Enable PowerShell Script Block Logging (EventCode 4104) across all endpoints via Group Policy
      owner: IT Operations
      due: 48h
  hunt_leads:
    - lead: Search for high-entropy PowerShell command lines or blocks containing common framework function names
      technique_id: T1059.001
      data_needed:
        - EventCode 4104 log data
      priority: medium
      confidence: medium
      disposition: convert_to_detection
  mitigation_plan:
    - priority: medium
      action: Implement Constrained Language Mode (CLM) for standard users to limit the effectiveness of offensive PowerShell toolkits
      owner: System Administration
      addresses: T1059.001
---

Security operations teams can identify the use of offensive PowerShell toolkits by leveraging EventCode 4104 (Script Block Logging). This logging mechanism captures the full content of executed PowerShell blocks, which is essential for visibility into encoded or obfuscated commands that would otherwise be obscured in standard process creation logs. By monitoring for specific strings associated with well-known frameworks like PowerSploit, Empire, and PowerSharpPack, defenders can detect activities related to credential theft, persistence, and lateral movement. This detection strategy is a fundamental requirement for environments where PowerShell is a primary vector for post-exploitation activities and provides the granular telemetry necessary to identify unauthorized access attempts before significant impact occurs.

## Impact

Successful exploitation using these offensive toolkits enables attackers to perform post-exploitation activities such as credential dumping from memory, lateral movement across the network using stolen tokens, and the establishment of persistence via registry or scheduled task modifications. Failure to detect these activities at the execution stage significantly increases the risk of data exfiltration and complete system compromise within the Windows environment.

## Recommendation

Deploy the provided Sigma rule and ensure PowerShell operational logging is enabled. Prioritize the ingestion of EventCode 4104 logs into the SIEM and tune the detection based on legitimate administrative scripting behavior within the environment.
