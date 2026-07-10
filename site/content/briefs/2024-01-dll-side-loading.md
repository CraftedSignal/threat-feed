---
title: Potential DLL Side-Loading via Trusted Microsoft Programs
slug: 2024-01-dll-side-loading
description: This rule detects potential DLL side-loading attempts by identifying trusted Microsoft programs (WinWord.exe, EXPLORER.EXE, w3wp.exe, DISM.EXE) running from non-standard paths or after being renamed to evade defenses.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - execution
  - windows
  - dll side-loading
vendors:
  - Microsoft
products:
  - Microsoft Word
  - Microsoft Windows
  - Microsoft Internet Information Services
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
    description: Detects trusted Microsoft programs (WinWord.exe, EXPLORER.EXE, w3wp.exe, DISM.EXE) running from non-standard paths, indicating potential DLL side-loading.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1574.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Renamed Trusted Microsoft Program Execution
    description: Detects execution of renamed trusted Microsoft programs, a potential indicator of DLL side-loading attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies potential DLL side-loading attempts, a technique used by adversaries to evade defenses. The technique involves exploiting the DLL search order vulnerability in trusted Microsoft programs such as WinWord.exe, EXPLORER.EXE, w3wp.exe, and DISM.EXE. Attackers rename or move these executables to non-standard paths and load malicious DLLs. By doing so, the malicious code is executed within the memory space of a trusted process, potentially bypassing security controls and evading detection. The original Elastic detection rule was created on 2020/09/03 and last updated on 2026/04/07. This activity matters to defenders as it allows attackers to execute malicious code with elevated privileges while blending in with legitimate system processes.

## Attack Chain

1.  Attacker gains initial access to the system.
2.  Attacker identifies a vulnerable, trusted Microsoft program (e.g., WinWord.exe, EXPLORER.EXE).
3.  Attacker copies or moves the targeted executable to a non-standard directory.
4.  Attacker renames the executable (optional).
5.  Attacker places a malicious DLL in the same directory as the renamed/moved executable. This DLL is designed to be loaded by the trusted program when it starts.
6.  Attacker executes the renamed/moved executable.
7.  The executable loads the malicious DLL due to DLL search order hijacking.
8.  The malicious DLL executes arbitrary code, achieving persistence, privilege escalation, or other malicious objectives.

## Impact

Successful DLL side-loading can lead to arbitrary code execution within the context of a trusted process. This allows attackers to bypass application whitelisting and other security controls. The impact can range from malware installation and data exfiltration to complete system compromise. This technique is often employed in targeted attacks and can be difficult to detect due to the legitimate appearance of the host process.

## Recommendation

*   Deploy the Sigma rule `Potential DLL Side-Loading via Trusted Microsoft Programs` to detect renamed or relocated trusted Microsoft programs. Tune the rule for your environment by whitelisting legitimate software updates or custom applications that may trigger false positives.
*   Enable process creation logging with command-line arguments to capture the full path of executed processes. This will provide the data needed to accurately identify processes running from non-standard locations (log source: process_creation).
*   Monitor file modifications and creations in directories where trusted Microsoft programs are located. This can help identify the presence of malicious DLLs (log source: file_event).
