---
title: Suspicious Microsoft Workflow Compiler Rename
slug: 2024-01-03-workflow-compiler-rename
description: Detection of the renaming of microsoft.workflow.compiler.exe, a technique used by attackers to evade security controls and potentially execute arbitrary code for privilege escalation or persistence.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lolbin
  - defense-evasion
  - living-off-the-land
  - masquerading
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Microsoft.Workflow.Compiler.exe
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1127
    technique_name: Trusted Developer Utilities Proxy Execution
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Microsoft.Workflow.Compiler/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md#atomic-test-6---microsoftworkflowcompilerexe-payload-execution
rules:
  - title: Detect Suspicious Microsoft Workflow Compiler Rename
    description: Detects the renaming of microsoft.workflow.compiler.exe, which can indicate an attempt to evade security controls.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1036.003
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious Microsoft Workflow Compiler Execution
    description: Detects execution of renamed microsoft.workflow.compiler.exe, indicating potential malicious activity.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1127
    data_sources:
      - process_creation
      - windows
  - title: Detect Microsoft Workflow Compiler spawning suspicious processes
    description: Detects Microsoft Workflow Compiler (renamed or not) spawning suspicious child processes
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1127
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This brief focuses on the suspicious renaming of the Microsoft Workflow Compiler (microsoft.workflow.compiler.exe), a legitimate but rarely used executable typically found in C:\Windows\Microsoft.NET\Framework64\v4.0.30319. Attackers may rename this file to masquerade malicious activity and bypass security solutions that rely on file name-based detection. This technique can be employed by various threat actors, including ransomware groups like BlackByte, to execute arbitrary code, escalate privileges, and maintain persistence on compromised systems. The LOLBAS Project documents this binary as a potential avenue for malicious code execution. This activity is significant because it represents a living-off-the-land tactic (LOTL) that is harder to detect than custom malware.

## Attack Chain

1. An attacker gains initial access to the system (e.g., through phishing or exploiting a vulnerability).
2. The attacker identifies Microsoft.Workflow.Compiler.exe in C:\Windows\Microsoft.NET\Framework64\v4.0.30319.
3. The attacker renames Microsoft.Workflow.Compiler.exe to a different name (e.g., svchost.exe) using a command-line tool like `rename`.
4. The attacker executes the renamed executable with malicious parameters or a payload.
5. The renamed Microsoft Workflow Compiler executes arbitrary code, bypassing file name-based security controls.
6. The attacker achieves privilege escalation by exploiting the trust associated with the original executable.
7. The attacker establishes persistence by scheduling the renamed executable to run automatically.
8. The attacker uses the compromised system to move laterally, exfiltrate data, or deploy ransomware.

## Impact

Successful renaming and execution of the Microsoft Workflow Compiler can lead to significant compromise, allowing attackers to bypass security measures and execute arbitrary code. This can lead to privilege escalation, persistence, and further malicious activities such as data theft or ransomware deployment. The BlackByte ransomware group has been known to use similar LOLBIN techniques, and the ease of renaming the file makes it a popular choice for attackers looking to evade detection.

## Recommendation

*   Monitor process creation events (Sysmon EventID 1 or Windows Event Log Security 4688) for the execution of renamed Microsoft Workflow Compiler processes using the provided Sigma rule `Detect Suspicious Microsoft Workflow Compiler Execution`.
*   Implement endpoint detection and response (EDR) solutions to collect and analyze process telemetry, including process names, original file names, parent processes, and command-line arguments.
*   Deploy the Sigma rule `Detect Suspicious Microsoft Workflow Compiler Rename` to identify instances where `Microsoft.Workflow.Compiler.exe` is renamed.
*   Investigate any alerts generated by the Sigma rules, paying close attention to the parent processes, command-line arguments, and destination hosts.
*   Enable Sysmon process creation logging to activate the rules above.
