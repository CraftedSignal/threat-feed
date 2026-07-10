---
title: Suspicious MS Office Child Process
slug: 2024-01-03-suspicious-office-child-process
description: This rule detects suspicious child processes spawned by Microsoft Office applications, indicating potential exploitation or malicious macros used for initial access, command execution, defense evasion, and discovery activities.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - initial-access
  - execution
  - defense-evasion
  - discovery
  - windows
vendors:
  - Microsoft
products:
  - Microsoft Office
  - Word
  - PowerPoint
  - Excel
mitre_ttps:
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
    technique_id: T1203
    technique_name: Exploitation for Client Execution
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
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1049
    technique_name: System Network Connections Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1057
    technique_name: Process Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
cves:
  - id: CVE-2023-36028
    cvss: 9.8
    epss: 0.02859
references:
  - https://www.elastic.co/blog/vulnerability-summary-follina
rules:
  - title: Suspicious MS Office Child Process - CommandLine
    description: Detects suspicious child processes of MS Office applications based on command-line arguments
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1059.003
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious MS Office Child Process - System Binary
    description: Detects suspicious system binaries being launched from MS Office applications
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1059.003
      - T1218.005
      - T1218.010
      - T1566.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies suspicious child processes of frequently targeted Microsoft Office applications such as Word, PowerPoint, and Excel. These child processes are often launched during the exploitation of Office applications or from documents containing malicious macros. The rule focuses on detecting processes like `powershell.exe`, `cmd.exe`, `mshta.exe`, and others that are not typically legitimate child processes of Office applications. This activity is often associated with initial access via phishing and subsequent command execution for defense evasion or discovery. The rule is designed to identify potential compromises stemming from malicious Office documents targeting Windows systems.

## Attack Chain

1. A user receives a phishing email with a malicious Office document (e.g., Word, Excel) attached.
2. The user opens the malicious document, which contains a malicious macro or exploits a vulnerability (e.g., CVE-2023-36028).
3. Upon opening, the document executes the embedded malicious macro or exploit.
4. The macro or exploit spawns a suspicious child process such as `powershell.exe` or `cmd.exe`.
5. The spawned process executes commands to download and execute a payload from a remote server.
6. The payload establishes persistence via registry modifications or scheduled tasks.
7. The attacker performs discovery actions using tools like `whoami.exe`, `ipconfig.exe`, or `net.exe` to gather system information.
8. The attacker moves laterally within the network to compromise additional systems and achieve their objectives, such as data exfiltration or ransomware deployment.

## Impact

A successful attack leveraging malicious Office documents can lead to initial access, allowing attackers to execute arbitrary code, establish persistence, and move laterally within the network. This can result in data theft, system compromise, and potentially ransomware deployment. The rule aims to detect these initial stages of compromise to prevent further damage.

## Recommendation

*   Deploy the Sigma rule "Suspicious MS Office Child Process - CommandLine" to your SIEM and tune for your environment to detect suspicious command-line arguments used by child processes spawned from MS Office applications.
*   Enable Sysmon process creation logging (Event ID 1) to improve the fidelity of process creation events and activate the Sigma rules above.
*   Review and harden macro execution policies within your organization to prevent the execution of malicious macros in Office documents.
*   Monitor process creations with parent processes being MS Office applications and child processes executing system binaries or command interpreters such as `cmd.exe`, `powershell.exe`, and `wscript.exe`.
