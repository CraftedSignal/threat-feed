---
title: Suspicious Process Creation via WMIC.exe
slug: 2026-07-wmic-suspicious-process
description: A high-severity threat involves adversaries abusing `wmic.exe` to create new processes like `rundll32` or `powershell` on Windows systems, a technique observed in ransomware campaigns such as Ryuk, Hive, and Conti, indicating post-compromise execution.
date: "2026-07-03T14:57:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ransomware
  - living-off-the-land
  - execution
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: Detects WMIC executing 'process call create' with suspicious calls to processes such as 'rundll32', 'regsrv32', etc.
    confidence_band: high
references:
  - https://thedfirreport.com/2020/10/08/ryuks-return/
  - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ransomware-hive-conti-avoslocker
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_wmic_susp_process_creation.yml
rules:
  - title: Detect Suspicious Process Created Via Wmic.EXE
    description: Detects WMIC executing 'process call create' with suspicious child processes or command-line arguments like 'rundll32', 'bitsadmin', 'powershell', or common temporary paths.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

This brief details the suspicious use of `wmic.exe` by threat actors to execute arbitrary commands, specifically via the "process call create" functionality. This method allows for the creation of new processes on local or remote Windows systems. Frequently employed by ransomware operators, including groups associated with Ryuk, Hive, and Conti, this technique serves as a post-compromise execution mechanism to launch malicious payloads, establish persistence, or facilitate lateral movement within a compromised network. Although no specific campaign identifiers are provided for the exploitation of this method, its use has been consistently observed in various attacks since at least late 2020. Adversaries leverage legitimate Windows tools like `wmic.exe` to evade detection, making it crucial for defenders to identify and monitor such activity to prevent the progression of attacks.

## Impact

Successful exploitation of this technique by adversaries typically leads to the execution of malicious code, often culminating in severe outcomes such as ransomware deployment (e.g., data encryption by Ryuk, Hive, Conti), data exfiltration, system compromise, and significant business disruption. The use of `wmic.exe` as an execution vector indicates an attacker has already gained a foothold, and unchecked activity can lead to a full network compromise, rendering systems inoperable and causing substantial financial and reputational damage to affected organizations.

## Recommendation

*   Deploy the `Detect Suspicious Process Created Via Wmic.EXE` Sigma rule to your SIEM and tune it for your environment.
*   Enable Sysmon process-creation logging to ensure the necessary telemetry for the `Detect Suspicious Process Created Via Wmic.EXE` rule is collected.
*   Regularly review `wmic.exe` process creation events for unusual child processes or command-line arguments, especially those containing `rundll32`, `powershell`, or `bitsadmin`.
