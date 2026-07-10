---
title: Potential Evasion via Filter Manager
slug: 2024-01-29-filter-manager-evasion
description: Adversaries may abuse the Filter Manager Control Program (fltMC.exe) to unload filter drivers, evading defenses like EDR and antivirus.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - filter-manager
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/001/
  - https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes
rules:
  - title: Detect Filter Manager Unload Activity
    description: Detects the use of fltMC.exe to unload filter drivers, which can be used to evade defenses.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Filter Manager Unload Activity from Non-System Paths
    description: Detects fltMC.exe execution from non-system paths to evade defenses.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Filter Manager Control Program (fltMC.exe) is a legitimate Windows utility used to manage and query filter drivers loaded on a system. These filter drivers, often called minifilters, are used by many security products, including EDR and antivirus solutions, to intercept and modify I/O requests. Adversaries can abuse fltMC.exe to unload these minifilters, effectively disabling security controls and evading detection. This technique is particularly effective because fltMC.exe is a signed Microsoft binary, making it less likely to be flagged by standard application control policies. The targeting is broad, affecting any Windows system with vulnerable filter drivers and inadequate process monitoring. This is a common post-exploitation tactic.

## Attack Chain

1.  The attacker gains initial access to the target system via other means.
2.  The attacker identifies security software utilizing minifilters.
3.  The attacker uses `fltMC.exe` with the `unload` argument to attempt to disable a targeted minifilter.
4.  The command `fltMC.exe unload <filter_name>` is executed, where `<filter_name>` specifies the driver to unload.
5.  Windows validates the request. If the attacker has sufficient privileges and the filter allows unloading, the driver is unloaded.
6.  The unloaded filter driver is no longer active, and its protections are bypassed.
7.  The attacker proceeds with malicious activities (e.g., malware execution, data exfiltration) without the filter's interference.
8.  The attacker attempts to remove traces of the activity by deleting logs or other artifacts.

## Impact

Successful exploitation allows attackers to bypass security controls implemented by filter drivers, such as real-time malware detection, file system monitoring, and behavior-based detection. This can lead to successful malware execution, data exfiltration, or other malicious activities that would otherwise be prevented. The impact is significant, especially in environments heavily reliant on filter drivers for security.

## Recommendation

*   Monitor process creation events for `fltMC.exe` executions with the `unload` argument using the provided Sigma rule to identify potential evasion attempts.
*   Implement strict access controls on `fltMC.exe` to limit its usage to authorized personnel only.
*   Investigate any identified instances of `fltMC.exe` being used to unload filter drivers, focusing on the parent process and the targeted driver.
*   Review and harden endpoint detection and response (EDR) configurations to ensure that the EDR solution can detect malicious activity even if filter drivers are unloaded.
*   Consider implementing application control policies to restrict the execution of `fltMC.exe` by unauthorized users or processes.
*   Monitor the Windows Security Event Logs and Sysmon logs for process creation events related to `fltMC.exe`.
*   Use the provided Sigma rule to detect suspicious usage of `fltMC.exe` and tune it for your environment.
