---
title: Suspicious Whoami Process Activity
slug: 2024-01-whoami-discovery
description: The `whoami` command is being used by an attacker to enumerate user, group, and privilege information on a Windows system, potentially indicating post-exploitation discovery activity after initial compromise or privilege escalation.
date: "2024-01-03T18:30:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
references:
  - https://attack.mitre.org/techniques/T1033/
  - https://attack.mitre.org/techniques/T1069/
rules:
  - title: Whoami Executed by WMI Provider Host
    description: Detects execution of whoami.exe with wsmprovhost.exe as a parent process, which is often indicative of malicious WMI activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1033
    data_sources:
      - process_creation
      - windows
  - title: Whoami Executed by Web Server Process
    description: Detects execution of whoami.exe with w3wp.exe (IIS worker process) as a parent process, indicating potential web server compromise.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1033
    data_sources:
      - process_creation
      - windows
  - title: Whoami Executed by WMIPRVSE
    description: Detects execution of whoami.exe with WMIPRVSE.exe as a parent process, which is often indicative of malicious WMI activity.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1033
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

The `whoami` command is a built-in Windows utility that displays the current user, group memberships, and privileges. While legitimate use exists, adversaries frequently leverage `whoami` post-exploitation to gain situational awareness, determine the current user's context, check the success of privilege escalation attempts, and map out further actions within the compromised environment. This command is particularly useful when executed within the context of system-level accounts, suggesting potential lateral movement or attempts to access sensitive resources. This activity is commonly seen across various threat actors and attack vectors, and this detection rule aims to identify anomalous usage patterns that deviate from standard administrative or user behaviors.

## Attack Chain

1. The attacker gains initial access to a Windows system via an exploit, compromised credentials, or other initial access vector (e.g., phishing).
2. The attacker executes a privilege escalation exploit or technique to gain higher privileges on the system.
3. After successful privilege escalation (or already operating with elevated privileges), the attacker executes the `whoami` command via `cmd.exe`, `powershell.exe`, or other command interpreters.
4. The `whoami` command is executed with no specific arguments, or with arguments such as `/groups` or `/priv`, to gather information about the current user's privileges and group memberships.
5. The attacker parses the output of the `whoami` command to identify valuable information about the system's configuration and available privileges.
6. This information is used to plan subsequent actions, such as lateral movement, credential dumping, or data exfiltration.
7. The attacker may then use the gathered information to target specific accounts or resources within the environment.

## Impact

Successful exploitation can lead to privilege escalation, lateral movement, and ultimately data exfiltration or other malicious activities. While the `whoami` command itself is not directly damaging, its usage is a strong indicator of post-exploitation reconnaissance. Detecting and responding to this activity early can prevent further damage and limit the attacker's ability to achieve their objectives. The execution of `whoami` by system accounts may expose sensitive configuration details and assist threat actors in escalating privileges or moving laterally within the network.

## Recommendation

*   Enable Sysmon process creation logging to activate the rules below.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
*   Investigate any execution of `whoami.exe` with a suspicious parent process (e.g., wsmprovhost.exe, w3wp.exe, wmiprvse.exe, rundll32.exe, regsvr32.exe) based on the Sigma rule.
