---
title: Local SxS Shared Module DLL Hijacking
slug: 2024-11-sxs-dll-hijacking
description: Adversaries may abuse shared modules in local Side-by-Side (SxS) folders to execute malicious payloads by instructing the Windows module loader to load DLLs from arbitrary local paths, potentially bypassing security controls.
date: "2024-11-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dll-hijacking
  - execution
  - defense-evasion
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1129
    technique_name: Shared Modules
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
references:
  - https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection
  - https://attack.mitre.org/techniques/T1129/
  - https://attack.mitre.org/techniques/T1574/
  - https://attack.mitre.org/techniques/T1574/001/
rules:
  - title: Detect DLL Creation in Local SxS Folder
    description: Detects the creation of DLL files in a local application SxS folder (application.exe.local), which could indicate DLL hijacking.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1574.001
    data_sources:
      - file_event
      - windows
  - title: Detect DLL Modification in Local SxS Folder
    description: Detects modification of DLL files in a local application SxS folder (application.exe.local), which could indicate DLL hijacking.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1574.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Attackers can exploit the Windows Side-by-Side (SxS) feature, specifically the application.exe.local folder, to load malicious DLLs. This technique involves placing a malicious DLL within the SxS folder, tricking a legitimate application into loading it instead of the intended DLL. This circumvents standard module loading order. The initial Elastic detection rule was created in 2020/10/28, and updated 2026/04/07. Defenders should be aware of this technique as it can be used to achieve code execution and potentially bypass application whitelisting or other security measures. This technique affects Windows systems and the impact is significant due to the potential for arbitrary code execution.

## Attack Chain

1.  The attacker gains initial access to the system (e.g., through phishing or exploiting a vulnerability).
2.  The attacker identifies a legitimate application vulnerable to DLL hijacking via the SxS folder (application.exe.local).
3.  The attacker creates a malicious DLL file, mimicking the name of a legitimate DLL that the target application attempts to load.
4.  The attacker places the malicious DLL into the application's SxS folder (application.exe.local).
5.  The target application is executed.
6.  The Windows module loader searches for the required DLL within the application's SxS folder first.
7.  The module loader loads the malicious DLL instead of the legitimate one.
8.  The malicious DLL executes its payload, granting the attacker code execution within the context of the legitimate application, potentially leading to further compromise or lateral movement.

## Impact

A successful DLL hijacking attack can lead to arbitrary code execution within the context of a legitimate application. This can allow attackers to bypass security controls, escalate privileges, install malware, or steal sensitive data. While the exact number of victims is unknown, DLL hijacking remains a prevalent technique, and this specific variation targeting local SxS shared modules increases the risk. Successful exploitation allows for defense evasion and persistence within the compromised environment.

## Recommendation

*   Monitor file creation events for DLL files within application.exe.local directories using the Sigma rule provided to detect potential malicious DLLs being placed in those folders.
*   Implement application whitelisting to restrict which applications can execute on a system, mitigating the risk of unauthorized DLL loading.
*   Enable Sysmon file creation and process creation logging to improve visibility into file system activity related to DLL loading.
*   Regularly audit and validate the integrity of DLLs within application directories.
*   Deploy the provided Sigma rules to detect malicious DLL creation or modifications in SxS folders.
