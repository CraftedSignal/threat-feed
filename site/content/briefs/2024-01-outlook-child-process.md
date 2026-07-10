---
title: Suspicious Microsoft Outlook Child Processes
slug: 2024-01-outlook-child-process
description: Detects suspicious child processes spawned by Microsoft Outlook, commonly associated with spear phishing attacks and the execution of malicious payloads.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - initial-access
  - execution
  - defense-evasion
  - phishing
  - windows
vendors:
  - Microsoft
products:
  - Outlook
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
    technique_id: T1204
    technique_name: User Execution
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
references:
  - https://attack.mitre.org/techniques/T1566/
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1204/
  - https://attack.mitre.org/techniques/T1218/
rules:
  - title: Suspicious Outlook Child Process - Command Interpreter
    description: Detects command interpreters (cmd.exe, powershell.exe, wscript.exe, cscript.exe) spawned by Outlook, which is indicative of potential phishing or malware activity.
    platform: sigma
    severity: high
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
  - title: Suspicious Outlook Child Process - System Binary
    description: Detects specific system binaries (mshta.exe, regsvr32.exe, installutil.exe) spawned by Outlook, which can indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - initial_access
    techniques:
      - T1218.004
      - T1218.005
      - T1218.010
      - T1566.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This rule identifies suspicious child processes of Microsoft Outlook, a common indicator of spear phishing campaigns. Attackers often use malicious attachments or embedded links in phishing emails to trigger the execution of malicious code when a user opens the email or attachment. This code then spawns child processes like PowerShell, cmd.exe, or other system binaries to perform further malicious activities, such as downloading malware, establishing persistence, or exfiltrating data. The rule focuses on detecting these anomalous parent-child process relationships to identify potential initial access attempts. This activity can lead to a full system compromise. This rule is designed to catch potential post-exploitation activity originating from compromised email clients and is applicable to a wide range of Windows environments.

## Attack Chain

1.  A user receives a spear phishing email with a malicious attachment (e.g., a Word document with a malicious macro).
2.  The user opens the attachment in Microsoft Outlook, triggering the execution of the embedded malicious code (e.g., VBA macro).
3.  The malicious code executes and spawns a child process, such as `powershell.exe`, `cmd.exe`, or `mshta.exe`, from `outlook.exe`.
4.  The child process executes a command to download a malicious payload from a remote server.
5.  The downloaded payload is saved to disk and executed, establishing persistence using techniques like registry modification or scheduled tasks.
6.  The malware performs reconnaissance activities, gathering information about the system and network.
7.  The malware establishes a command and control (C2) channel to communicate with the attacker.
8.  The attacker uses the C2 channel to issue commands and exfiltrate sensitive data, deploy ransomware, or perform other malicious activities.

## Impact

A successful attack can lead to the compromise of the user's system, potentially granting the attacker access to sensitive data, credentials, and other resources on the network. This can result in data breaches, financial losses, reputational damage, and disruption of business operations. While the number of impacted users is variable, successful exploitation can lead to wider network compromise impacting numerous systems.

## Recommendation

*   Deploy the Sigma rule `Suspicious Outlook Child Process - Command Interpreter` to your SIEM to detect command interpreters spawned by Outlook, and tune for your environment.
*   Deploy the Sigma rule `Suspicious Outlook Child Process - System Binary` to your SIEM to detect system binaries spawned by Outlook, and tune for your environment.
*   Enable process creation logging with command line arguments via Windows Security Event Logs or Sysmon to provide visibility for the Sigma rules.
*   Monitor for the execution of processes listed in the Sigma rules (`powershell.exe`, `cmd.exe`, `mshta.exe`, etc.) with `outlook.exe` as the parent process.
*   Implement email security measures, such as spam filtering and anti-phishing training, to reduce the risk of users receiving malicious emails.
