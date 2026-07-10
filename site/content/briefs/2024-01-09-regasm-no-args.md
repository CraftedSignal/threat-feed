---
title: RegAsm Executed Without Command Line Arguments
slug: 2024-01-09-regasm-no-args
description: The execution of regasm.exe without command-line arguments is often indicative of process injection and potential code execution, which could lead to privilege escalation, persistence, or data compromise.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - regasm
  - process-injection
  - defense-evasion
  - windows
vendors:
  - Microsoft
products:
  - RegAsm
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://attack.mitre.org/techniques/T1218/009/
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.009/T1218.009.md
  - https://lolbas-project.github.io/lolbas/Binaries/Regasm/
rules:
  - title: Detect Regasm Executed Without Command Line Arguments
    description: Detects instances of regasm.exe running without any command line arguments, which is indicative of process injection.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1218.009
    data_sources:
      - process_creation
      - windows
  - title: Detect RegAsm Running from Unusual Location
    description: Detects RegAsm running from a non-standard directory, potentially indicating suspicious or malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.009
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The detection analytic identifies instances where regasm.exe is executed without command-line arguments. This behavior is suspicious because RegAsm (Assembly Registration Tool) typically requires arguments specifying which assemblies to register or unregister. The absence of command-line arguments often indicates that the process has been injected into by another process, and its normal execution flow has been altered to evade standard defenses. The detection focuses on endpoint telemetry related to process execution, parent-child relationships, and command-line parameters. It is crucial for defenders because successful exploitation can lead to arbitrary code execution within a trusted process.

## Attack Chain

1.  An attacker gains initial access to the system through an unspecified method.
2.  The attacker injects malicious code into a running process or spawns a new process (e.g., PowerShell).
3.  The injected code identifies and targets regasm.exe for process injection.
4.  The attacker leverages the process injection technique to execute regasm.exe without command-line arguments.
5.  RegAsm, now running without arguments, may execute attacker-controlled code due to the injected malicious payload.
6.  The injected code performs malicious actions such as modifying system configurations, creating persistence mechanisms, or escalating privileges.
7.  The attacker leverages the compromised process to move laterally within the network and access sensitive data.
8.  The final objective could be data exfiltration, system disruption, or deployment of ransomware.

## Impact

Successful exploitation can allow attackers to execute arbitrary code within the context of a trusted system process, potentially bypassing application control policies and detection mechanisms. This can lead to privilege escalation, persistence, lateral movement, and data compromise. While the exact number of victims and sectors targeted are unknown, any environment where RegAsm is present is potentially vulnerable, especially developer workstations and servers.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM to detect instances of RegAsm executing without command-line arguments and tune for your environment.
*   Enable Sysmon process-creation logging to provide the necessary telemetry for the detection rules.
*   Investigate any detected instances of RegAsm executing without arguments to determine the root cause and scope of the compromise.
*   Review and harden endpoint security policies to prevent process injection attacks.
