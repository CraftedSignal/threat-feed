---
title: Potential DLL Side-Loading via Trusted Microsoft Programs
slug: 2026-05-dll-side-loading
description: This rule detects potential DLL side-loading attempts by identifying instances of Windows trusted programs (WinWord.exe, EXPLORER.EXE, w3wp.exe, DISM.EXE) being started after being renamed or from a non-standard path, which is a common technique to evade defenses by side-loading a malicious DLL into the memory space of a trusted process.
date: "2026-05-04T14:17:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - execution
  - dll-side-loading
  - windows
vendors:
  - Microsoft
products:
  - WinWord.exe
  - EXPLORER.EXE
  - w3wp.exe
  - DISM.EXE
  - Microsoft Defender XDR
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_execution_suspicious_explorer_winword.toml
  - https://attack.mitre.org/techniques/T1036/
  - https://attack.mitre.org/techniques/T1574/
  - https://attack.mitre.org/techniques/T1574/001/
rules:
  - title: Potential DLL Side-Loading via Trusted Microsoft Programs
    description: Detects instances of trusted Windows programs (WinWord.exe, EXPLORER.EXE, w3wp.exe, DISM.EXE) being started from non-standard paths, indicating potential DLL side-loading.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036
      - T1574.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Name and Path Combination
    description: Detects when a process with a known trusted name is executed from an unusual path, potentially indicating DLL side-loading or other masquerading techniques.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036
      - T1574.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies instances of Windows trusted programs such as WinWord.exe, EXPLORER.EXE, w3wp.exe, and DISM.EXE executing from unusual paths or after being renamed, which may indicate DLL side-loading. DLL side-loading is a defense evasion technique where a malicious DLL is placed in the same directory as a legitimate executable. When the executable runs, it may load the malicious DLL instead of the legitimate one, allowing the attacker to execute arbitrary code within the context of the trusted process. The detection logic focuses on process executions that deviate from standard installation paths. The targeted processes are commonly used and often whitelisted, making this a potent technique for adversaries to bypass security controls.

## Attack Chain

1.  The attacker gains initial access to the system (e.g., through phishing or exploitation of a vulnerability).
2.  The attacker identifies a trusted Windows program vulnerable to DLL side-loading (WinWord.exe, EXPLORER.EXE, w3wp.exe, or DISM.EXE).
3.  The attacker drops a malicious DLL into a directory where the trusted program is expected to load DLLs from, often alongside a renamed or copied version of the legitimate executable.
4.  Alternatively, the attacker renames the trusted program and places it in a non-standard path.
5.  The attacker executes the renamed or moved trusted program from the non-standard path.
6.  The trusted program loads the malicious DLL due to DLL search order hijacking.
7.  The malicious DLL executes arbitrary code within the context of the trusted process.
8.  The attacker achieves persistence, elevates privileges, or performs other malicious activities, potentially evading detection due to the trusted process context.

## Impact

A successful DLL side-loading attack allows the attacker to execute arbitrary code within the context of a trusted Microsoft process. This can lead to privilege escalation, persistence, and further compromise of the system. Since the malicious code is running within a trusted process, it can bypass application whitelisting and other security controls, making it difficult to detect. This can lead to data theft, system disruption, or the installation of malware.

## Recommendation

*   Deploy the Sigma rule "Potential DLL Side-Loading via Trusted Microsoft Programs" to your SIEM to detect suspicious executions of trusted programs from non-standard paths or with modifications.
*   Enable Sysmon process creation logging (Event ID 1) to provide the necessary data for the Sigma rule to function correctly.
*   Review and tune the exclusion paths in the Sigma rule to avoid false positives from legitimate software updates, custom enterprise applications, or virtual environments.
*   Monitor process execution paths using the Sigma rule "Potential DLL Side-Loading via Trusted Microsoft Programs" and investigate any deviations from standard installation paths.
