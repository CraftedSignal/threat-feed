---
title: Suspicious WMI Image Load from MS Office
slug: 2024-01-suspicious-wmi-image-load
description: Adversaries may exploit Windows Management Instrumentation (WMI) to execute code stealthily, bypassing traditional security measures by loading `wmiutils.dll` from Microsoft Office applications, potentially indicating malicious execution.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - wmi
  - image load
  - office
  - execution
vendors:
  - Microsoft
products:
  - WINWORD.EXE
  - EXCEL.EXE
  - POWERPNT.EXE
  - MSPUB.EXE
  - MSACCESS.EXE
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
references:
  - https://medium.com/threatpunter/detecting-adversary-tradecraft-with-image-load-event-logging-and-eql-8de93338c16
rules:
  - title: Suspicious WMI Image Load from MS Office
    description: Detects suspicious image load of wmiutils.dll from Microsoft Office processes, indicating potential WMI abuse for code execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1047
    data_sources:
      - image_load
      - windows
  - title: Suspicious Office Application Spawning WMIC
    description: Detects Microsoft Office applications spawning WMIC.exe, which is often used for malicious purposes.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies suspicious image loading of `wmiutils.dll` from Microsoft Office processes (WINWORD.EXE, EXCEL.EXE, POWERPNT.EXE, MSPUB.EXE, MSACCESS.EXE). Adversaries can use this technique to execute code and evade traditional parent/child processes spawned from Microsoft Office products. This behavior may indicate adversarial activity where child processes are spawned via Windows Management Instrumentation (WMI).

## Attack Chain

1. User opens a malicious Microsoft Office document (e.g., Word, Excel).
2. The document contains a macro or exploit that triggers the execution of WMI commands.
3. The Office application spawns a WMI process or utilizes existing WMI infrastructure.
4. The WMI process loads the `wmiutils.dll` library, which is unusual for normal Office operations.
5. The WMI commands execute malicious code, potentially downloading or executing further payloads.
6. The attacker establishes persistence through WMI event subscriptions or other methods.
7. The attacker performs lateral movement using WMI to execute commands on other systems.

## Impact

Successful exploitation allows attackers to execute arbitrary code, establish persistence, and move laterally within the network, potentially leading to data exfiltration, system compromise, or ransomware deployment. While the number of victims is unknown, this technique can be used in targeted attacks against organizations that heavily rely on Microsoft Office applications.

## Recommendation

*   Deploy the Sigma rule "Suspicious WMI Image Load from MS Office" to your SIEM and tune for your environment.
*   Enable Sysmon event ID 7 (Image Loaded) logging for comprehensive image load monitoring as suggested in the [setup instructions](https://ela.st/sysmon-event-7-setup).
*   Monitor process creation events for Microsoft Office applications spawning WMI-related processes (e.g., `wbemtest.exe`, `wmic.exe`) to detect potential WMI abuse.
*   Implement network segmentation to limit lateral movement in case of a successful WMI-based attack.
