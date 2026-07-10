---
title: Suspicious Mofcomp Activity Leading to WMI Abuse
slug: 2024-01-mofcomp-activity
description: Attackers may leverage the mofcomp.exe utility to compile malicious MOF files, enabling them to manipulate the Windows Management Instrumentation (WMI) repository for persistence or execution of arbitrary code.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - execution
  - persistence
  - wmi
  - mofcomp
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
references:
  - https://attack.mitre.org/techniques/T1047/
  - https://attack.mitre.org/techniques/T1546/
  - https://attack.mitre.org/techniques/T1546/003/
rules:
  - title: Mofcomp Activity
    description: Detects the execution of mofcomp.exe with a .mof file as an argument, excluding system account and known safe parent processes related to SQL Server.
    platform: sigma
    severity: low
    tactics:
      - execution
      - persistence
    techniques:
      - T1047
      - T1546.003
    data_sources:
      - process_creation
      - windows
  - title: Mofcomp Execution from Suspicious Parent Process
    description: Detects mofcomp.exe execution from unusual parent processes, indicating potential abuse.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The mofcomp.exe utility is a legitimate Windows tool used to compile Managed Object Format (MOF) files, which define classes and namespaces within the Windows Management Instrumentation (WMI) repository. Attackers can abuse mofcomp.exe to inject malicious code into WMI, enabling persistent execution or other nefarious activities. This technique is often employed to establish persistence by creating WMI event subscriptions that trigger malicious actions when specific system events occur. The described detection rule focuses on identifying suspicious mofcomp.exe executions by filtering out benign activity associated with SQL Server (ScenarioEngine.exe) and the SYSTEM account, highlighting potentially malicious uses of the utility. This activity is a common post-exploitation technique.

## Attack Chain

1.  An attacker gains initial access to the target system through methods not covered in this brief.
2.  The attacker drops a malicious MOF file onto the system. This file contains code designed to manipulate WMI.
3.  The attacker executes mofcomp.exe to compile the malicious MOF file. The command line includes the path to the MOF file.
4.  Mofcomp.exe compiles the MOF file and modifies the WMI repository according to the MOF file's instructions.
5.  The MOF file creates or modifies WMI event filters, consumers, and bindings, establishing a WMI event subscription.
6.  A specific system event triggers the WMI event subscription.
7.  The WMI event subscription executes a malicious payload, such as running a script or executable.
8.  The attacker achieves persistence or executes arbitrary code on the system, maintaining their access or performing other malicious actions.

## Impact

Successful exploitation allows attackers to achieve persistence on the compromised system, as well as execute arbitrary code. By manipulating WMI, attackers can maintain a hidden presence and control system behavior. This can lead to data theft, system compromise, or further propagation within the network. The creation of WMI event subscriptions is a common persistence mechanism, making it difficult to detect and remove.

## Recommendation

*   Deploy the Sigma rule "Mofcomp Activity" to your SIEM to detect suspicious executions of mofcomp.exe (rule provided below).
*   Investigate any process execution where `process.name : "mofcomp.exe"` and `process.args : "*.mof"` but `user.id` is not `"S-1-5-18"` as per the provided EQL query.
*   Monitor for new or modified WMI event filters, consumers, and bindings to identify potentially malicious WMI event subscriptions.
*   Implement restrictions on who can execute mofcomp.exe and modify the WMI repository to limit the attack surface.
*   Enable process monitoring and command-line auditing to capture detailed information about mofcomp.exe executions.
