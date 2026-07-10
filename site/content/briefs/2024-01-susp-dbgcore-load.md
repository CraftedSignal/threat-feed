---
title: Suspicious Loading of Dbgcore/Dbghelp DLLs from Uncommon Location
slug: 2024-01-susp-dbgcore-load
description: The loading of dbgcore.dll or dbghelp.dll from unusual locations like user directories indicates potential credential dumping or EDR evasion attempts by malicious actors.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - defense-evasion
  - dll-injection
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://blog.axelarator.net/hunting-for-edr-freeze/
  - https://www.zerosalarium.com/2025/09/EDR-Freeze-Puts-EDRs-Antivirus-Into-Coma.html
  - https://www.splunk.com/en_us/blog/security/you-bet-your-lsass-hunting-lsass-access.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/image_load/image_load_win_susp_dbgcore_dbghelp_load.yml
rules:
  - title: Suspicious Dbgcore/Dbghelp DLL Load from Uncommon Location
    description: Detects loading of dbgcore.dll or dbghelp.dll from uncommon locations such as user directories.
    platform: sigma
    severity: high
    tactics:
      - credential-access
      - defense-evasion
    techniques:
      - T1003
      - T1562.001
    data_sources:
      - image_load
      - windows
  - title: Suspicious Process Loading Dbghelp/Dbgcore from User Profile
    description: Detects processes loading Dbghelp or Dbgcore DLLs from within user profile directories, indicating potential malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
    techniques:
      - T1003
    data_sources:
      - image_load
      - windows
rules_count: 2
---

Attackers may load dbgcore.dll or dbghelp.dll from unusual locations to leverage the MiniDumpWriteDump function for malicious purposes. This function can be abused for credential dumping, specifically targeting the LSASS process, or for defense evasion by suspending processes, effectively freezing or disabling EDR/AV solutions. The observed behavior involves loading these DLLs from locations such as user directories, which is uncommon for legitimate software execution. This activity can be a strong indicator of post-exploitation activity aimed at gaining unauthorized access to sensitive information or hindering security measures. The threat specifically focuses on Windows systems.

## Attack Chain

1. An attacker gains initial access to a Windows system through an exploit or compromised credentials (not detailed in source).
2. The attacker uploads or creates a malicious executable in a non-standard directory (e.g., `C:\Users\Public\`).
3. The malicious executable attempts to load either `dbgcore.dll` or `dbghelp.dll`.
4. The `ImageLoad` event is generated when the system loads one of the DLLs.
5. The malicious program uses the `MiniDumpWriteDump` function within the loaded DLL.
6. The attacker utilizes the function to create a memory dump of the LSASS process to obtain credentials.
7. Alternatively, the attacker might use the DLL to suspend or freeze security processes, like EDR or AV.
8. The attacker exfiltrates the dumped credentials or continues with further malicious activities, such as lateral movement.

## Impact

Successful exploitation can lead to the theft of sensitive credentials stored in the LSASS process, enabling lateral movement and further compromise of the network. The potential impact includes unauthorized access to critical systems, data breaches, and disruption of services. Freezing or disabling EDR/AV solutions allows attackers to operate undetected, significantly increasing the risk of a successful attack.

## Recommendation

*   Deploy the Sigma rule `Suspicious Dbgcore/Dbghelp DLL Load from Uncommon Location` to your SIEM to detect this specific behavior (rules).
*   Investigate any `image_load` events where `dbgcore.dll` or `dbghelp.dll` are loaded from suspicious paths like user directories (rules, logsource).
*   Monitor process creation events for processes spawned from unusual locations attempting to access LSASS memory (references).
*   Enable and review Windows `image_load` events to gain visibility into loaded DLLs (logsource).
