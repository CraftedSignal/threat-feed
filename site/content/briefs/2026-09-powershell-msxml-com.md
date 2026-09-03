---
title: Abuse of PowerShell MSXML COM Objects for Network Interaction
slug: 2026-09-powershell-msxml-com
description: Adversaries leverage the MSXML2 COM object within PowerShell scripts to facilitate network communication and potential code execution.
date: "2026-09-03T13:40:56Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - execution
  - powershell
  - detection-engineering
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Adversaries may abuse PowerShell commands and scripts for execution.
    confidence_band: high
rules:
  - title: Detect PowerShell MSXML COM Object Usage
    description: Detects usage of MSXML2 COM objects within PowerShell scripts, a technique often used to perform network requests for payload staging or exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104)
      owner: IT Operations
      due: 72h
      evidence: Required for detection of script-based COM object abuse
  hunt_leads:
    - lead: Search for historical instances of MSXML2 usage in PowerShell logs
      technique_id: T1059.001
      data_needed:
        - Event ID 4104
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: COM object usage is rare in standard administrative scripts
  mitigation_plan:
    - priority: medium
      action: Implement constrained PowerShell language mode
      owner: IT Security
      addresses: General PowerShell abuse
      evidence: Defense-in-depth practice
---

Adversaries frequently abuse PowerShell's ability to interact with COM objects to perform stealthy network operations or fetch remote payloads. Specifically, the use of `MsXml2.ServerXmlHttp` or `MsXml2.XMLHTTP` allows scripts to bypass traditional browser-based security controls when performing HTTP requests. This technique is often observed during the post-exploitation phase, where attackers attempt to download secondary stages or exfiltrate data. By invoking these COM objects, a script can instantiate an HTTP client directly within the PowerShell process memory, making the activity harder to distinguish from legitimate background administrative traffic. Defenders should monitor for the instantiation of these specific COM objects in conjunction with PowerShell, as this is a common TTP used by botnets and remote access trojans to establish C2.

## Impact

Successful abuse of this technique enables an attacker to maintain persistent communication with command-and-control infrastructure, download additional malicious tools, and exfiltrate sensitive data from the host. This activity has been observed in various botnet campaigns where PowerShell is used for automated payload delivery.

## Recommendation

- Enable PowerShell Script Block Logging (Event ID 4104) to capture the full command line and script body.
- Deploy the provided Sigma rule to detect the specific combination of 'New-Object', '-ComObject', and MSXML components in script blocks.
- Baseline administrative scripts in the environment to reduce false positives associated with legitimate use of COM objects for network tasks.
