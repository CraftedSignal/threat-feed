---
title: Unusual Parent-Child Relationship Detection
slug: 2024-01-unusual-parent-child
description: This rule identifies Windows programs run from unexpected parent processes, which could indicate masquerading or other strange activity on a system, potentially indicating process injection, masquerading, access token manipulation, or parent PID spoofing.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - defense-evasion
  - windows
  - process-injection
  - masquerading
  - access-token-manipulation
  - parent-pid-spoofing
vendors:
  - Microsoft
products:
  - Microsoft Defender XDR
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1055
    technique_name: Process Injection
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1134
    technique_name: Access Token Manipulation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1134
    technique_name: Access Token Manipulation
references:
  - https://github.com/sbousseaden/Slides/blob/master/Hunting%20MindMaps/PNG/Windows%20Processes%20TH.map.png
  - https://www.andreafortuna.org/2017/06/15/standard-windows-processes-a-brief-reference/
  - https://www.elastic.co/security-labs/elastic-security-labs-steps-through-the-r77-rootkit
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/privilege_escalation_unusual_parentchild_relationship.toml
rules:
  - title: Suspicious Parent Process of AutoChk
    description: Detects AutoChk executed by a process other than smss.exe, which could indicate masquerading or privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1036.009
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Parent Process of DllHost
    description: Detects DllHost executed by a process other than services.exe or svchost.exe, which could indicate masquerading or privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1036.009
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Child Process of smss.exe
    description: Detects unusual child processes spawned by smss.exe, which might indicate malicious activity attempting to masquerade as a legitimate system process.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1036.009
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

This detection identifies Windows programs executed with unexpected parent processes, which may indicate masquerading, process injection, or other anomalous behavior. The detection logic focuses on deviations from established parent-child process relationships within the Windows operating system. This rule leverages data from multiple sources, including Elastic Defend, CrowdStrike, Microsoft Defender XDR, SentinelOne Cloud Funnel, Sysmon, and Windows Security Event Logs, to enhance detection coverage. This is important for defenders as unusual parent-child process relationships can be indicative of various malicious activities, including privilege escalation and defense evasion techniques employed by threat actors. The rule aims to provide early detection of potentially malicious activities by identifying deviations from the expected process execution patterns.

## Attack Chain

1.  The attacker gains initial access to the system (e.g., through phishing or exploiting a vulnerability).
2.  The attacker executes a malicious payload that attempts to masquerade as a legitimate process.
3.  The malicious process is launched with an unexpected parent process, deviating from normal Windows process relationships. For example, `autochk.exe` running without `smss.exe` as its parent.
4.  The malicious process attempts to inject code into other processes for privilege escalation or defense evasion, leveraging techniques like process hollowing.
5.  The injected code gains elevated privileges, allowing the attacker to perform sensitive actions on the system.
6.  The attacker uses the elevated privileges to move laterally within the network, compromising additional systems.
7.  The attacker attempts to maintain persistence by creating scheduled tasks or modifying registry keys.
8.  The attacker achieves their final objective, such as data exfiltration or deploying ransomware.

## Impact

A successful attack exploiting unusual parent-child relationships can lead to privilege escalation, allowing attackers to gain control of the compromised system. This can result in data breaches, system downtime, and financial losses. The rule aims to mitigate these risks by detecting suspicious process executions early in the attack chain. While the exact number of potential victims and sectors targeted is not explicitly mentioned, the broad applicability of Windows systems makes this a widespread threat.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM and tune for your environment to detect unusual parent-child process relationships (see `rules` section).
*   Enable process creation logging with command line arguments in your Windows environment using Sysmon or Windows Security Event Logs to ensure the necessary data is available for detection.
*   Investigate and baseline common parent-child process relationships in your environment to reduce false positives.
*   Integrate your SIEM with threat intelligence feeds to identify known malicious processes and their associated parent processes.
*   Configure endpoint detection and response (EDR) solutions like Elastic Defend, CrowdStrike, Microsoft Defender XDR, and SentinelOne to collect and analyze process execution data (see `setup` section in the source URL).
*   Refer to the investigation guide linked in the source URL to triage alerts related to unusual parent-child process relationships.
