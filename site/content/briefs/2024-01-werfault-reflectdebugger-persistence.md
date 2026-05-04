---
title: Werfault ReflectDebugger Persistence via Registry Modification
slug: 2024-01-werfault-reflectdebugger-persistence
description: Attackers may establish persistence by modifying the ReflectDebugger registry key associated with Windows Error Reporting to execute arbitrary code when Werfault is invoked with the '-pr' parameter.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - registry_modification
  - werfault
vendors:
  - Microsoft
  - Elastic
  - Crowdstrike
  - SentinelOne
products:
  - Elastic Defend
  - Microsoft Defender XDR
affected_os:
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
rules:
  - title: Werfault ReflectDebugger Registry Modification
    description: Detects modification of the ReflectDebugger registry key, used for persistence.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1112
      - T1546.012
    data_sources:
      - registry_set
      - windows
  - title: Werfault Execution with -pr Parameter
    description: Detects execution of Werfault with the -pr parameter, which can trigger malicious code execution if the ReflectDebugger key is set.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1546.012
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers can abuse the Windows Error Reporting (Werfault) service to establish persistence on a compromised system. This is achieved by modifying the ReflectDebugger registry key. When Werfault is executed with the `-pr` parameter, it will execute the debugger specified in the ReflectDebugger registry key. This allows attackers to execute arbitrary code every time the Windows Error Reporting utility is triggered. The technique involves modifying specific registry paths associated with the ReflectDebugger. This behavior has been documented as a persistence mechanism in malware analysis reports.

## Attack Chain

1.  The attacker gains initial access to the system through unspecified means.
2.  The attacker attempts to modify the Windows Error Reporting ReflectDebugger registry key.
3.  The attacker modifies the ReflectDebugger value within one of the following registry paths: `HKLM\Software\Microsoft\Windows\Windows Error Reporting\Hangs\ReflectDebugger`, `\REGISTRY\MACHINE\Software\Microsoft\Windows\Windows Error Reporting\Hangs\ReflectDebugger`, or `MACHINE\Software\Microsoft\Windows\Windows Error Reporting\Hangs\ReflectDebugger`.
4.  The attacker sets the ReflectDebugger value to a malicious executable or script.
5.  The attacker triggers Werfault.exe with the `-pr` parameter, either manually or through a system event.
6.  Werfault.exe executes the attacker-controlled code specified in the ReflectDebugger registry value.
7.  The attacker achieves persistence, as the malicious code is executed each time Werfault is triggered with the `-pr` parameter.

## Impact

Successful exploitation allows attackers to achieve persistence on the targeted system. This can lead to the execution of arbitrary code, potentially resulting in data theft, further malware installation, or complete system compromise. The impact is limited by the permissions of the Werfault process. While no specific victim counts are available, this technique can affect any Windows system where the attacker can modify the registry.

## Recommendation

*   Deploy the Sigma rule `Werfault ReflectDebugger Registry Modification` to detect unauthorized modifications to the ReflectDebugger registry key (logsource: `registry_set`, rule title).
*   Enable Sysmon process creation logging to detect the execution of Werfault with the `-pr` parameter.
*   Monitor registry events for changes to the specific ReflectDebugger paths mentioned in the overview section (`HKLM\Software\Microsoft\Windows\Windows Error Reporting\Hangs\ReflectDebugger`).
