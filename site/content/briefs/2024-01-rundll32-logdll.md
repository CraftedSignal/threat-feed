---
title: Rundll32 Execution with Log.DLL
slug: 2024-01-rundll32-logdll
description: Detects the execution of rundll32 with 'log.dll' as a command-line argument, indicative of Lotus Blossom Chrysalis backdoor activity and DLL sideloading attempts.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Lotus Blossom
tags:
  - rundll32
  - dll-sideloading
  - lotus-blossom
  - chrysalis-backdoor
vendors:
  - Microsoft
  - Bitdefender
products:
  - Windows
  - Bitdefender Submission Wizard
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
references:
  - https://attack.mitre.org/techniques/T1574/002/
  - https://www.rapid7.com/blog/post/tr-chrysalis-backdoor-dive-into-lotus-blossoms-toolkit/
  - https://attack.mitre.org/groups/G0065/
rules:
  - title: Rundll32 Execution with Log.DLL
    description: Detects rundll32 executing log.dll, a common tactic for DLL sideloading attacks, especially associated with Lotus Blossom.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1574.002
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Rundll32 Execution Path
    description: Detects rundll32 executions from uncommon paths.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1574.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief focuses on the abuse of `rundll32.exe` to execute malicious DLLs, specifically `log.dll`, a technique associated with the Lotus Blossom group's Chrysalis backdoor. The attacker places a rogue `log.dll` in a location such as `%AppData%\Bluetooth` and leverages `rundll32.exe` to invoke a specific function within the DLL (e.g., `LogInit`). This execution decrypts and runs shellcode. While some legitimate applications like the Bitdefender Submission Wizard also use `log.dll`, they are susceptible to DLL sideloading attacks, making this detection crucial for identifying malicious activity that bypasses traditional defenses. This campaign was first reported in 2026 and continues to be a relevant threat.

## Attack Chain

1.  The attacker gains initial access, often through social engineering or exploiting software vulnerabilities (not specified in source).
2.  A malicious `log.dll` is placed in a writable directory, such as `%AppData%\Bluetooth`, mimicking a legitimate DLL location.
3.  The attacker uses `rundll32.exe` to execute the malicious `log.dll` with a specific function call (e.g., `rundll32.exe log.dll,LogInit`).
4.  `Rundll32.exe` loads and executes the `log.dll`.
5.  The `LogInit` function in `log.dll` decrypts embedded shellcode.
6.  The shellcode is injected into a legitimate process or executed directly, establishing persistence or escalating privileges.
7.  The injected shellcode connects to a command-and-control (C2) server to download additional payloads or receive instructions.
8.  The attacker performs actions on the compromised system, such as data exfiltration, lateral movement, or installing additional malware.

## Impact

Successful exploitation can lead to complete system compromise, data theft, and the installation of persistent backdoors. The Lotus Blossom group has been known to target organizations across various sectors. The ability to bypass traditional security measures through DLL sideloading makes this a high-impact threat. Even legitimate software can become an attack vector.

## Recommendation

*   Deploy the Sigma rule `Rundll32 Execution with Log.DLL` to detect malicious `rundll32.exe` executions using `log.dll` (logsource: process_creation).
*   Investigate any `rundll32.exe` process executions with `log.dll` as a command-line argument, especially when originating from unusual paths (Sigma rule `Rundll32 Execution with Log.DLL`).
*   Monitor for suspicious file creations or modifications in `%AppData%\Bluetooth` or other common DLL sideloading locations (logsource: file_event).
*   Implement application control policies to restrict the execution of `rundll32.exe` from untrusted locations.
*   Audit systems for DLL sideloading vulnerabilities in legitimate applications.
