---
title: Potential Port Monitor or Print Processor Registration Abuse
slug: 2024-01-port-monitor-print-processor-abuse
description: This rule detects registry modifications indicative of privilege escalation and persistence attempts by adversaries abusing port monitors and print processors to execute malicious DLLs with SYSTEM privileges on Windows systems.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - persistence
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/
  - https://attack.mitre.org/techniques/T1547/
  - https://attack.mitre.org/techniques/T1547/010/
  - https://attack.mitre.org/techniques/T1547/012/
  - https://attack.mitre.org/tactics/TA0004/
  - https://attack.mitre.org/tactics/TA0003/
rules:
  - title: Suspicious Print Monitor DLL Registration
    description: Detects the registration of a DLL as a print monitor by a non-SYSTEM user.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1547.010
    data_sources:
      - registry_set
      - windows
  - title: Suspicious Print Processor DLL Registration
    description: Detects the registration of a DLL as a print processor by a non-SYSTEM user.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1547.012
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Adversaries may abuse port monitors and print processors to run malicious DLLs during system boot, achieving privilege escalation and persistence. This technique involves modifying specific registry keys related to port monitors and print processors, allowing the execution of arbitrary code with SYSTEM privileges. The targeted registry paths include those under `HKLM\\SYSTEM\\*ControlSet*\\Control\\Print\\Monitors\\*` and `HKLM\\SYSTEM\\*ControlSet*\\Control\\Print\\Environments\\Windows*\\Print Processors\\*`. The Winnti Group has been known to leverage this technique. This activity matters to defenders because successful exploitation leads to SYSTEM-level code execution, enabling complete system compromise.

## Attack Chain

1. An adversary gains initial access to the system through unspecified means.
2. The adversary identifies a vulnerable or misconfigured printing service.
3. The adversary modifies the registry to point a port monitor or print processor entry to a malicious DLL. The registry keys targeted include `HKLM\\SYSTEM\\*ControlSet*\\Control\\Print\\Monitors\\*` and `HKLM\\SYSTEM\\*ControlSet*\\Control\\Print\\Environments\\Windows*\\Print Processors\\*`.
4. The system is rebooted or the print spooler service is restarted.
5. The malicious DLL is loaded by the print spooler service, executing with SYSTEM privileges.
6. The malicious DLL performs actions such as installing backdoors, escalating privileges, or injecting into other processes.
7. The adversary achieves persistence by maintaining the malicious DLL entry in the registry, ensuring it's loaded on subsequent reboots.

## Impact

Successful exploitation allows adversaries to execute arbitrary code with SYSTEM privileges, leading to complete system compromise. This can result in data theft, installation of backdoors, or further propagation within the network. The number of victims and sectors targeted is not specified in the source.

## Recommendation

*   Deploy the Sigma rule "Potential Port Monitor or Print Processor Registration Abuse" to your SIEM and tune for your environment.
*   Investigate any registry modifications to `HKLM\\SYSTEM\\*ControlSet*\\Control\\Print\\Monitors\\*` or `HKLM\\SYSTEM\\*ControlSet*\\Control\\Print\\Environments\\Windows*\\Print Processors\\*` where the `registry.data.strings` value contains a DLL and the `user.id` is not `"S-1-5-18"`.
*   Implement application whitelisting to prevent unauthorized DLLs from being loaded as print processors or port monitors.
*   Monitor for new services or scheduled tasks that may be created by the malicious DLL.
