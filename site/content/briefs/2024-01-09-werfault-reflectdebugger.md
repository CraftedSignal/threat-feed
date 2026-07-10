---
title: Werfault ReflectDebugger Persistence Abuse
slug: 2024-01-09-werfault-reflectdebugger
description: Attackers can achieve persistence by modifying the ReflectDebugger registry key associated with Windows Error Reporting (Werfault) to execute arbitrary code when Werfault is invoked with the `-pr` parameter.
date: "2024-01-09T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - windows
  - registry
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://cocomelonc.github.io/malware/2022/11/02/malware-pers-18.html
  - https://attack.mitre.org/techniques/T1546/
  - https://attack.mitre.org/techniques/T1546/012/
  - https://attack.mitre.org/techniques/T1112/
rules:
  - title: Werfault ReflectDebugger Registry Modification
    description: Detects modification of the Werfault ReflectDebugger registry key, which can be abused for persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1112
      - T1546.012
    data_sources:
      - registry_set
      - windows
  - title: Werfault Process Execution with -pr Parameter
    description: Detects Werfault.exe execution with the -pr parameter, potentially indicating exploitation of ReflectDebugger.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1546.012
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers are known to abuse the Windows Error Reporting (Werfault) functionality to establish persistence on compromised systems. This involves manipulating the `ReflectDebugger` registry key, which is associated with Werfault's error handling process. By modifying this key, attackers can configure Werfault to execute arbitrary code whenever it is launched with the `-pr` parameter. This technique allows malicious actors to maintain a persistent presence on the system, as Werfault is a legitimate Windows utility and its execution is a normal part of system operation. This behavior was observed in late 2022, and targets unpatched Windows systems. Successful exploitation allows for code execution within a trusted process.

## Attack Chain

1.  Attacker gains initial access to the target system (e.g., through compromised credentials or exploitation of a separate vulnerability).
2.  The attacker attempts to identify the registry key associated with Werfault's ReflectDebugger.
3.  Attacker modifies the `HKLM\\Software\\Microsoft\\Windows\\Windows Error Reporting\\Hangs\\ReflectDebugger` registry key.
4.  The attacker sets the value of `ReflectDebugger` to a malicious executable or script.
5.  The attacker triggers Werfault by causing an application crash or invoking it directly with the `-pr` parameter.
6.  Werfault executes the malicious code specified in the `ReflectDebugger` registry value.
7.  The attacker gains persistent code execution on the system.
8.  The attacker leverages their persistent access for further malicious activities, such as data exfiltration or lateral movement.

## Impact

Successful exploitation allows attackers to achieve persistence on the compromised system. Although rated as low severity, the attacker can leverage this persistence to maintain access, escalate privileges, and conduct further malicious activities. This can lead to data theft, system compromise, or disruption of services. The number of victims is currently unknown, but the sectors most likely affected are those with unpatched Windows systems.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM to detect unauthorized modifications to the `ReflectDebugger` registry key.
*   Enable Sysmon registry event logging to monitor changes to the `HKLM\\Software\\Microsoft\\Windows\\Windows Error Reporting\\Hangs\\ReflectDebugger` key (logsource: registry_set).
*   Implement enhanced monitoring and alerting for registry changes in the specified paths to detect and respond to similar threats in the future (see content section).
*   Isolate any affected systems from the network immediately to prevent further propagation of malicious code (see content section).
