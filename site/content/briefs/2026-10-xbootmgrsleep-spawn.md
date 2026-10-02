---
title: Suspicious Child Process Execution via XBootMgrSleep.exe
slug: 2026-10-xbootmgrsleep-spawn
description: Detection of potentially unauthorized process execution using the Microsoft-signed Windows Performance Toolkit utility XBootMgrSleep.exe to bypass security controls.
date: "2026-10-02T12:13:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - execution
  - windows-performance-toolkit
vendors:
  - Microsoft
products:
  - Windows Performance Toolkit
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: XBootMgrSleep.exe is a Microsoft-signed Windows Performance Toolkit binary that can execute an arbitrary executable after a delay.
    confidence_band: high
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/XBootMgrSleep/
rules:
  - title: Uncommon Child Process Spawned From XBootMgrSleep.EXE
    description: Detects a process other than the expected XBootMgr.exe spawned by XBootMgrSleep.exe, indicating potential misuse for arbitrary code execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule to monitor for XBootMgrSleep.exe child processes.
      owner: Detection Engineering
      due: 72h
      evidence: Rule presence in security documentation.
---

XBootMgrSleep.exe is a utility distributed as part of the Microsoft Windows Performance Toolkit. Security research identifies this binary as a potential Living-off-the-Land (LotL) vector, as it possesses the inherent capability to execute an arbitrary secondary binary after a specified delay. Because the tool is Microsoft-signed, adversaries may leverage it to execute malicious payloads or secondary stage implants while evading reputation-based detection mechanisms that trust binaries within the Windows Kits directory. Monitoring for unusual child processes spawned by this specific utility is critical for identifying potential persistence or execution staging, as the tool is rarely required in standard end-user or workstation environments.

## Impact

Successful exploitation of this technique allows attackers to maintain execution of unauthorized code under the umbrella of a trusted, digitally signed Microsoft process, potentially bypassing application control policies and environment monitoring that relies solely on process path or signature verification.

## Recommendation

Deploy the provided Sigma rule to detect non-standard child processes initiated by the XBootMgrSleep.exe binary.

* Enable Sysmon process-creation logging (Event ID 1) to capture the full command line and parent process information required for this detection.
* Establish a baseline for legitimate usage of the Windows Performance Toolkit in your environment to minimize false positives from authorized diagnostic scripts.
* Investigate any alert triggered by this rule to determine if the spawned process is a known administrative utility or an unauthorized artifact.
