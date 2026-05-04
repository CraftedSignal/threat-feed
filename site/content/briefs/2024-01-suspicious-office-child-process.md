---
title: Suspicious MS Office Child Process
slug: 2024-01-suspicious-office-child-process
description: Detects suspicious child processes of Microsoft Office applications, indicating potential exploitation or malicious macros for initial access, defense evasion, and execution.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - initial-access
  - defense-evasion
  - execution
  - discovery
  - windows
vendors:
  - Microsoft
products:
  - Microsoft Office
  - Microsoft Word
  - Microsoft Excel
  - Microsoft PowerPoint
  - Outlook
affected_os:
  - Windows
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
references:
  - https://www.elastic.co/blog/vulnerability-summary-follina
  - https://attack.mitre.org/techniques/T1566/
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1203/
  - https://attack.mitre.org/techniques/T1218/
  - https://attack.mitre.org/techniques/T1016/
  - https://attack.mitre.org/techniques/T1033/
  - https://attack.mitre.org/techniques/T1049/
  - https://attack.mitre.org/techniques/T1057/
  - https://attack.mitre.org/techniques/T1082/
rules:
  - title: Suspicious MS Office Child Process
    description: Detects suspicious child processes of Microsoft Office applications
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1059.003
      - T1218
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Office Application spawning CertUtil
    description: Detects certutil.exe spawned by MS Office apps, often used for downloading malicious payloads.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1218.012
      - T1566.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies suspicious child processes spawned by Microsoft Office applications (Word, PowerPoint, Excel, Outlook), which are commonly targeted for initial access via malicious documents or macro exploitation. The rule focuses on identifying anomalous process executions originating from these applications, a tactic often employed to execute arbitrary code or download additional payloads. Attackers leverage Office applications due to their widespread use and inherent scripting capabilities. Successful exploitation can lead to arbitrary code execution, lateral movement, and data exfiltration. This detection helps defenders identify and respond to potential security breaches originating from Microsoft Office applications, reducing the attack surface and minimizing potential damage. The rule specifically looks for processes like `cmd.exe`, `powershell.exe`, `mshta.exe`, `wscript.exe`, and others being spawned by Office applications.

## Attack Chain

1.  A user receives a malicious Microsoft Office document (e.g., Word, Excel) via email or downloads it from a compromised website.
2.  The user opens the document, triggering the execution of a malicious macro or exploitation of a vulnerability within the Office application.
3.  The Office application (e.g., `winword.exe`, `excel.exe`) spawns a suspicious child process such as `cmd.exe` or `powershell.exe`.
4.  The spawned process executes a command to download a malicious payload from a remote server using `bitsadmin.exe` or `certutil.exe`.
5.  The downloaded payload is a reverse shell or a malware dropper, which establishes a connection to an attacker-controlled server.
6.  The attacker gains initial access to the compromised system and attempts to escalate privileges and perform reconnaissance.
7.  The attacker uses discovery commands with `net.exe`, `ipconfig.exe`, `tasklist.exe`, and `whoami.exe` to map the environment and identify valuable targets.
8.  The attacker moves laterally to other systems within the network, aiming to compromise critical assets and achieve their objectives, such as data theft or ransomware deployment.

## Impact

Successful exploitation can lead to arbitrary code execution, allowing attackers to gain initial access to the compromised system. This can result in data theft, installation of malware, lateral movement to other systems, and ultimately, significant disruption to business operations. The widespread use of Microsoft Office makes it a prime target, potentially affecting a large number of users and organizations. Failure to detect and respond to these attacks can result in significant financial losses, reputational damage, and compromise of sensitive data.

## Recommendation

*   Enable process creation logging (Sysmon Event ID 1 or Windows Security Event Logs) to ensure the visibility required to detect suspicious child processes.
*   Deploy the Sigma rule `Suspicious MS Office Child Process` to your SIEM and tune the rule based on your environment to reduce false positives.
*   Investigate any alerts generated by the `Suspicious MS Office Child Process` Sigma rule by examining the parent process tree and associated network connections.
*   Implement application control policies to restrict the execution of unauthorized processes from Microsoft Office applications.
*   Regularly update Microsoft Office applications to patch known vulnerabilities.
*   Block known malicious domains or IPs associated with malware delivery and command and control, based on threat intelligence feeds and IOCs from external sources.
