---
title: Suspicious Execution via Windows Command Debugging Utility
slug: 2024-07-cdb-execution
description: Adversaries can abuse the Windows command line debugging utility cdb.exe to execute commands or shellcode from non-standard paths, evading traditional security measures.
date: "2026-05-04T14:17:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lolbas
  - defense-evasion
  - windows
vendors:
  - Microsoft
  - Crowdstrike
  - SentinelOne
  - Elastic
products:
  - Microsoft Defender XDR
  - Elastic Defend
  - CrowdStrike
  - SentinelOne Cloud Funnel
  - Sysmon
  - Windows Security Event Logs
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Cdb/
rules:
  - title: Execution via Windows Command Debugging Utility
    description: Detects suspicious execution of cdb.exe from non-standard paths with specific command-line arguments used for defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.005
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: CDB.Exe Execution with Suspicious Parameters
    description: Detects cdb.exe execution with -cf, -c, or -pd parameters
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.005
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Windows command line debugging utility, cdb.exe, is a legitimate tool used for debugging applications. However, adversaries can exploit it to execute unauthorized commands or shellcode, bypassing security measures. This can be achieved by running cdb.exe from non-standard installation paths and using specific command-line arguments to execute malicious commands. The LOLBAS project documents this technique, highlighting its potential for defense evasion. This activity has been observed across various environments, necessitating detection strategies that focus on identifying anomalous executions of cdb.exe.

## Attack Chain

1.  An attacker gains initial access to a Windows system.
2.  The attacker copies cdb.exe to a non-standard location (outside "Program Files" and "Program Files (x86)").
3.  The attacker executes cdb.exe with the `-cf`, `-c`, or `-pd` command-line arguments.
4.  These arguments are used to specify a command file or execute a direct command.
5.  The command file or command directly executes malicious code, such as shellcode.
6.  The malicious code performs actions such as creating new processes, modifying files, or establishing network connections.
7.  These actions allow the attacker to maintain persistence or escalate privileges.
8.  The ultimate goal is to evade defenses and execute arbitrary code on the system.

## Impact

Successful exploitation allows adversaries to execute arbitrary commands and shellcode on the affected system, potentially leading to complete system compromise. This can result in data theft, installation of malware, or further propagation within the network. The technique is effective at bypassing application whitelisting and other security controls that rely on standard execution paths.

## Recommendation

*   Deploy the Sigma rule "Execution via Windows Command Debugging Utility" to your SIEM to detect suspicious cdb.exe executions (see rules section).
*   Enable process creation logging via Sysmon or Windows Security Event Logs to provide the necessary data for the Sigma rule.
*   Implement application whitelisting to prevent execution of cdb.exe from non-standard paths.
*   Monitor process command lines for the `-cf`, `-c`, and `-pd` flags when cdb.exe is executed.
*   Investigate any instances of cdb.exe running from unusual directories to determine legitimacy.
