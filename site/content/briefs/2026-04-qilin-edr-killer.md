---
title: Qilin Ransomware EDR Killer Infection Chain
slug: 2026-04-qilin-edr-killer
description: Qilin ransomware employs a malicious msimg32.dll in a multi-stage infection chain to disable endpoint detection and response (EDR) solutions by evading detection and terminating EDR processes.
date: "2026-04-02T10:00:56Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - Qilin Ransomware
tags:
  - qilin
  - edr-killer
  - ransomware
  - defense-evasion
  - windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1574
    technique_name: Hijack Execution Flow
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1055
    technique_name: Process Injection
references:
  - https://blog.talosintelligence.com/qilin-edr-killer/
iocs:
  - type: file_name
    value: msimg32.dll
ioc_counts:
  file_name: 1
rules:
  - title: Detect Malicious msimg32.dll Load
    description: Detects the loading of msimg32.dll from a non-system directory, indicating potential DLL side-loading by the Qilin EDR killer.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1574.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Exception Handler Overwrite
    description: Detects modification of the exception handler dispatcher slot, a technique used by Qilin EDR killer.
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
    techniques:
      - T1564.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

The Qilin ransomware group is actively deploying a sophisticated EDR killer as part of their attack chain. The initial stage involves a malicious "msimg32.dll" that is likely side-loaded by a legitimate application. This DLL version triggers its malicious logic from within its DllMain function, leading to immediate execution upon loading. The EDR killer employs advanced evasion techniques, including neutralizing user-mode hooks, suppressing Event Tracing for Windows (ETW) event generation, and utilizing structured exception handling (SEH) and vectored exception handling (VEH) to obfuscate control flow. Once active, the EDR killer component loads helper drivers to access physical memory and terminate EDR processes. This allows the malware to disable over 300 different EDR drivers across a wide range of vendors, hindering incident response and enabling further malicious activity.

## Attack Chain

1.  A legitimate application loads the malicious "msimg32.dll", likely through DLL side-loading, triggering execution from within the DllMain function.
2.  The DLL allocates a heap buffer in process memory acting as a slot-policy table based on ntdll.dll's OptionalHeader.SizeOfCode, dividing the code region into 16-byte slots.
3.  The malware iterates over the export table of "ntdll.dll" to resolve virtual addresses of syscall stubs, specifically targeting those starting with "Nt".
4.  Based on resolved addresses, the malware marks corresponding entries in the slot-policy table with default or special policies, specifically targeting NtTraceEvent, NtTraceControl, and NtAlpcSendWaitReceivePort.
5.  The malware dynamically resolves ntdll!LdrProtectMrdata and invokes it to change the protection of the .mrdata section to writable.
6.  The loader overwrites the dispatcher slot within the .mrdata section with its own custom exception handler to intercept and modify exception handling.
7.  The custom exception handler manages breakpoint exceptions (0xCC), potentially as an anti-emulation technique.
8.  The EDR killer component loads helper drivers, "rwdrv.sys" for physical memory access and "hlpdrv.sys" to terminate EDR processes, after unregistering monitoring callbacks to prevent interference.

## Impact

Successful execution of the Qilin EDR killer can disable over 300 different EDR drivers, severely impairing the ability of security teams to detect and respond to threats. This can lead to increased dwell time for ransomware and other malicious activities, resulting in significant data breaches, financial losses, and reputational damage. With telemetry collection disabled, defenders lose visibility into process, memory, and network activity, making it difficult to investigate and contain the attack.

## Recommendation

*   Monitor for DLLs loaded from non-standard locations, specifically "msimg32.dll," using process creation logs to detect potential DLL side-loading attempts (rules in this brief).
*   Implement the Sigma rules provided in this brief to detect the modification of exception handler dispatchers, which is a key component of the EDR killer's evasion techniques.
*   Monitor for the loading of unsigned or untrusted drivers like "rwdrv.sys" and "hlpdrv.sys" using driver load events, as these are used to gain system privileges and terminate EDR processes.
*   Enable Sysmon process creation logging to capture detailed information about process execution, including command-line arguments and parent processes, to aid in the detection of malicious DLL loading.
*   Analyze process memory for evidence of user-mode hooks being neutralized or ETW event generation being suppressed. This requires more advanced memory forensics capabilities.
