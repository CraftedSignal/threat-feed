---
title: Regsvr32 Silent and Install Parameter DLL Loading
slug: 2024-01-03-regsvr32-dll-loading
description: Detection of regsvr32.exe being used with the silent and DLL install parameter to load a DLL, a technique used by RATs like Remcos and njRAT to execute arbitrary code.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Remcos
  - njRAT
tags:
  - lolbin
  - dll-loading
  - regsvr32
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://app.any.run/tasks/dc93ee63-050c-4ff8-b07e-8277af9ab939/
  - https://attack.mitre.org/techniques/T1218/010/
rules:
  - title: Regsvr32 Silent and Install Param Dll Loading
    description: Detects regsvr32.exe being used with the silent parameter and DLLInstall execution, often used by malware to load malicious DLLs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1218.010
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Regsvr32 Parent Process
    description: Detects regsvr32.exe being executed from suspicious parent processes such as cmd.exe or powershell.exe.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1218.010
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief focuses on the abuse of `regsvr32.exe`, a legitimate Microsoft Windows utility, to load and execute malicious DLLs. Attackers, including those using Remote Access Trojans (RATs) like Remcos and njRAT, leverage `regsvr32.exe` with the `/s` (silent) parameter and the `DLLInstall` function call. The activity is observed by analyzing process command-line arguments and parent process details from Endpoint Detection and Response (EDR) agents. This technique allows attackers to bypass application whitelisting and execute arbitrary code, maintain persistence, and compromise the system further. The detection described was published in splunk-escu on 2026-05-04.

## Attack Chain

1.  An attacker gains initial access via an unknown vector (e.g., phishing, exploit).
2.  The attacker deploys a malicious DLL on the compromised system.
3.  The attacker executes `regsvr32.exe` with the `/s` (silent) parameter and the `DLLInstall` function, for example: `regsvr32.exe /s /i:DLLInstall <malicious_dll_path>`.
4.  `Regsvr32.exe` loads the specified DLL.
5.  The DLLInstall function within the DLL executes, performing malicious actions. This could involve installing services, modifying registry keys, or injecting code into other processes.
6.  The attacker establishes persistence through registry modifications or scheduled tasks created by the DLL.
7.  The attacker executes arbitrary commands on the system, potentially installing additional malware or exfiltrating data.
8.  The attacker achieves their final objective, such as data theft, system disruption, or ransomware deployment.

## Impact

Successful exploitation can allow attackers to execute arbitrary code, bypass application whitelisting, and establish persistence on compromised systems. This can lead to data theft, system disruption, or ransomware deployment. The affected systems can be remotely controlled by the attacker, enabling further lateral movement within the network.

## Recommendation

*   Deploy the Sigma rule `Regsvr32 Silent and Install Param Dll Loading` to detect instances of `regsvr32.exe` being used with the `/s` and `/i` parameters.
*   Enable Sysmon process creation logging (Event ID 1) and Windows Event Log Security Auditing (Event ID 4688) to capture the necessary process and command-line information.
*   Investigate any instances of `regsvr32.exe` execution with the silent and DLLInstall parameters, paying close attention to the parent process and the DLL being loaded.
*   Implement application control policies to restrict the execution of `regsvr32.exe` or other LOLBins from untrusted locations.
