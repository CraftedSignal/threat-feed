---
title: Suspicious Explorer Child Process via DCOM
slug: 2024-01-30-suspicious-explorer-child-process
description: A suspicious Windows Explorer child process is detected, indicating potential exploitation of explorer.exe to launch malicious scripts or executables from a trusted parent process via DCOM.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - explorer.exe
  - dcom
  - windows
  - initial-access
  - defense-evasion
  - execution
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1559
    technique_name: Inter-Process Communication
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/initial_access_via_explorer_suspicious_child_parent_args.toml
  - https://attack.mitre.org/techniques/T1566/
  - https://attack.mitre.org/techniques/T1566/001/
  - https://attack.mitre.org/techniques/T1566/002/
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1059/003/
  - https://attack.mitre.org/techniques/T1059/005/
  - https://attack.mitre.org/techniques/T1559/
  - https://attack.mitre.org/techniques/T1559/001/
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1218/005/
  - https://attack.mitre.org/techniques/T1218/010/
  - https://attack.mitre.org/techniques/T1218/011/
rules:
  - title: Suspicious Explorer Child Process via DCOM - PowerShell
    description: Detects PowerShell spawned by explorer.exe via DCOM.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1559.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Explorer Child Process via DCOM - Cmd
    description: Detects cmd.exe spawned by explorer.exe via DCOM.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.003
      - T1559.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Explorer Child Process via DCOM - Mshta
    description: Detects mshta.exe spawned by explorer.exe via DCOM.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1218.005
      - T1559.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection identifies suspicious child processes spawned by `explorer.exe` on Windows systems, focusing on processes initiated via Component Object Model (COM) with arguments indicative of DCOM usage, such as `-Embedding`. Attackers may abuse the trusted status of `explorer.exe` to launch malicious payloads, bypassing security controls that might otherwise detect the execution of these payloads from less reputable parent processes. This activity is typically observed when a user clicks a malicious link or opens a weaponized document, leading to the execution of malicious scripts or binaries. The processes of interest include `cscript.exe`, `wscript.exe`, `powershell.exe`, `rundll32.exe`, `cmd.exe`, `mshta.exe`, and `regsvr32.exe`. This detection aims to identify these anomalous parent-child process relationships to uncover potential initial access, execution, and defense evasion attempts. The rule was last updated on 2026/04/07.

## Attack Chain

1.  A user receives a phishing email containing a malicious link or attachment (T1566, T1566.001, T1566.002).
2.  The user clicks the link or opens the attachment, triggering the execution of a malicious script or executable.
3.  The script or executable leverages Component Object Model (COM) to initiate `explorer.exe` with the `-Embedding` argument (T1559.001).
4.  `explorer.exe` then spawns a child process such as `powershell.exe`, `cmd.exe`, `mshta.exe`, `regsvr32.exe`, `cscript.exe`, `wscript.exe`, or `rundll32.exe` (T1059, T1218).
5.  The spawned process executes malicious commands or scripts, potentially downloading further payloads or establishing persistence.
6.  The attacker gains initial access to the system and can perform further actions like lateral movement, data exfiltration, or privilege escalation (TA0001, TA0002).
7.  The attacker attempts to evade defenses by leveraging a trusted process (`explorer.exe`) to execute malicious code (TA0005).
8.  The ultimate objective is often to deploy ransomware, steal sensitive data, or establish a persistent foothold on the compromised system.

## Impact

Successful exploitation can lead to complete system compromise, data theft, and potential ransomware deployment. While the number of victims and targeted sectors are unspecified, the nature of this attack can affect any Windows environment. The compromise occurs when a user interacts with a malicious file or link, resulting in the execution of arbitrary code under the guise of a trusted process. If successful, the attacker gains an initial foothold, leading to further malicious activities within the network.

## Recommendation

*   Deploy the "Suspicious Explorer Child Process" Sigma rule to your SIEM and tune for your environment (rule).
*   Enable process creation logging, specifically monitoring for parent-child relationships involving `explorer.exe` and scripting engines (logsource).
*   Review and update endpoint security policies to restrict the execution of potentially malicious scripts or executables from `explorer.exe`, especially when initiated via DCOM (rule).
*   Implement additional monitoring and alerting for similar suspicious activities involving explorer.exe to enhance detection capabilities and prevent recurrence (rule).
