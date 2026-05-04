---
title: Abuse of Windows Update Client for DLL Loading
slug: 2024-01-wuauclt-dll-load
description: The Windows Update Auto Update Client (wuauclt.exe) is being abused to load arbitrary DLLs, a defense evasion technique where malicious activity blends with legitimate Windows software by using specific process arguments and placing DLLs in writable paths.
date: "2024-01-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - execution
  - lolbas
  - windows
vendors:
  - Microsoft
products:
  - Windows Auto Update Client
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1129
    technique_name: Shared Modules
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1129
    technique_name: Shared Modules
references:
  - https://dtm.uk/wuauclt/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_execution_lolbas_wuauclt.toml
rules:
  - title: ImageLoad via Windows Update Auto Update Client
    description: Detects abuse of wuauclt.exe to load an arbitrary DLL via RunHandlerComServer and UpdateDeploymentProvider.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1129
      - T1218
    data_sources:
      - process_creation
      - windows
  - title: Suspicious wuauclt.exe Execution from Unusual Location
    description: Detects wuauclt.exe execution from a non-standard directory.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1218
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers are abusing the Windows Update Auto Update Client (wuauclt.exe) to execute arbitrary code by loading malicious DLLs. This technique allows malicious actors to evade defenses by masquerading their activity as legitimate Windows processes. The abuse involves using specific command-line arguments with wuauclt.exe to load a DLL from a user-writable directory. This behavior has been observed in various attacks aimed at evading traditional security measures. This is an effective defense evasion and execution technique, allowing attackers to execute code while blending in with normal system processes, potentially bypassing application control and other security mechanisms.

## Attack Chain

1. An attacker gains initial access to the system through an unrelated method.
2. The attacker places a malicious DLL in a directory writable by standard users, such as `C:\Users\<username>\`, `C:\ProgramData\`, `C:\Windows\Temp\`, or `C:\Windows\Tasks\`.
3. The attacker executes `wuauclt.exe` with the arguments `/RunHandlerComServer` and `/UpdateDeploymentProvider` along with the path to the malicious DLL. For example: `wuauclt.exe /RunHandlerComServer /UpdateDeploymentProvider /dll:<path_to_malicious_dll>`.
4. `wuauclt.exe` loads the specified malicious DLL.
5. The malicious DLL executes arbitrary code within the context of the `wuauclt.exe` process.
6. The malicious code performs its intended actions, such as establishing persistence, communicating with a C2 server, or escalating privileges.
7. The attacker may then use the compromised system as a foothold for lateral movement within the network.

## Impact

Successful exploitation allows attackers to execute arbitrary code within a trusted Windows process, potentially bypassing security controls and making detection more difficult. While specific victim counts are unavailable, this technique can be used in targeted attacks against organizations where defense evasion is a priority for the adversary. Successful execution can lead to complete system compromise, data theft, or further malicious activities.

## Recommendation

*   Deploy the Sigma rule `ImageLoad via Windows Update Auto Update Client` to detect the execution of `wuauclt.exe` with suspicious arguments.
*   Monitor process creation events for `wuauclt.exe` with the arguments `/RunHandlerComServer` and `/UpdateDeploymentProvider`, focusing on DLL paths in user-writable directories.
*   Enable Sysmon process-creation and image-load logging to improve visibility into this type of attack.
*   Audit DLLs loaded by `wuauclt.exe` and investigate any unsigned or unexpected DLLs.
