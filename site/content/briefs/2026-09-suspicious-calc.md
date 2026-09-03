---
title: Detection of Anomalous Windows Calculator Execution
slug: 2026-09-suspicious-calc
description: Detection of potential process masquerading or command-line exploitation attempts leveraging the Windows Calculator binary from non-standard system directories or with abnormal parameters.
date: "2026-09-03T12:37:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - suspicious-activity
  - evasion
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Detects suspicious use of 'calc.exe' with command line parameters or in a suspicious directory.
    confidence_band: high
rules:
  - title: Detect Suspicious Calculator Usage
    description: Detects anomalous use of 'calc.exe' with command line parameters or execution from outside standard Windows system directories
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1036
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to hunt for historical instances of anomalous calc.exe execution
      owner: Detection Engineering
      due: 72h
      evidence: Source provides standard detection logic for known PoC behavior
  hunt_leads:
    - lead: Process creation events for calc.exe outside of System32/SysWOW64
      technique_id: T1036
      data_needed:
        - Sysmon ID 1
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Rule definition in source
---

This detection covers the anomalous execution of 'calc.exe', the Windows Calculator binary, which is frequently used by security researchers and threat actors as a payload for proof-of-concept (PoC) code execution, process injection testing, or detection evasion. While 'calc.exe' is a standard utility, it should strictly reside within specific Windows system directories such as 'System32', 'SysWOW64', or 'WinSxS'. The execution of this binary from user-writable directories (e.g., 'C:\\Users\\Public\\' or 'C:\\Temp\\') or its invocation with unexpected command-line arguments is a common indicator of an attacker verifying execution flow following an exploit or conducting initial testing for post-exploitation persistence.

## Impact

Successful execution of payloads disguised as 'calc.exe' indicates that an attacker has achieved arbitrary code execution on the endpoint. If left undetected, this allows attackers to verify the stability of their environment access before pivoting to more intrusive activities like credential dumping, lateral movement, or ransomware deployment.

## Recommendation

Deploy the provided Sigma rule to monitor for suspicious process execution patterns. Ensure Sysmon or equivalent endpoint logging is active to capture the full command line and image path for 'calc.exe'. 

- Enable Sysmon Event ID 1 (Process Creation) to populate the required 'Image' and 'CommandLine' fields.
- Investigate any hits in your SIEM immediately, as legitimate system processes should not be running from unexpected directories or using parameters.
