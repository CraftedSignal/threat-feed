---
title: Potential Execution via FileFix Phishing Attack
slug: 2024-01-filefix-phishing
description: This rule detects potential execution of Windows commands or downloaded files via the browser's dialog box, indicative of a phishing attack where victims are tricked into copying and pasting malicious commands.
date: "2024-01-03T18:19:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - execution
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
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
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://mrd0x.com/filefix-clickfix-alternative/
rules:
  - title: Detect FileFix Phishing via Process Arguments
    description: Detects potential FileFix phishing attacks by monitoring process creations with specific parent process arguments related to browser dialog boxes.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1566.001
      - T1566.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Downloaded Executable Connecting Outbound
    description: Detects processes executed from the downloads directory initiating network connections, potentially indicating a malicious payload.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1071.001
      - T1204.002
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This detection identifies potential execution of Windows commands or downloaded files stemming from browser interactions, which is a common tactic in phishing campaigns. Attackers leverage phishing websites that instruct victims to copy and paste malicious commands into their systems. This technique bypasses traditional security measures that focus on file downloads or email attachments. The rule focuses on detecting processes such as PowerShell, curl, msiexec, and others, when they are spawned with specific parent process arguments related to browser dialog boxes and originate from user download folders. The targeted execution methods include command interpreters and system binaries. The detection is designed to catch scenarios where users are tricked into executing commands directly through their browsers, bypassing conventional security filters.

## Attack Chain

1.  The victim receives a phishing email or visits a compromised website.
2.  The website displays instructions prompting the user to copy a malicious command.
3.  The user, believing the instructions are legitimate, copies the command from the browser.
4.  The user pastes the command into a command prompt or PowerShell window.
5.  The command executes, potentially downloading and running a malicious payload.
6.  The payload establishes persistence, often by creating a scheduled task or modifying registry keys.
7.  The attacker gains remote access to the compromised system.
8.  The attacker performs lateral movement, seeking to compromise other systems within the network.

## Impact

A successful attack can lead to complete system compromise, data theft, and potential ransomware deployment. Victims in any sector are vulnerable if they interact with the phishing content. The impact includes financial loss, reputational damage, and disruption of business operations. If the attacker gains access to sensitive data, it could lead to regulatory fines and legal action. The copy-paste nature of the attack makes it difficult to detect with traditional endpoint security solutions.

## Recommendation

*   Deploy the Sigma rule `Detect FileFix Phishing via Process Arguments` to your SIEM to detect potential malicious process executions.
*   Enable process creation logging with command line arguments in your Windows environment to ensure the Sigma rule functions correctly.
*   Monitor network connections originating from processes spawned from user download directories using the Sigma rule `Detect Downloaded Executable Connecting Outbound`.
*   Educate users about the risks of copying and pasting commands from untrusted sources to mitigate the initial access vector (T1566).
*   Implement application control policies to restrict the execution of unauthorized programs, especially those located in user download folders, to prevent malicious file execution (T1204.002).
