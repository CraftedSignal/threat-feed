---
title: MpCmdRun.exe Used to Remove Defender Definitions
slug: 2024-01-09-mpcmdrun-definition-removal
description: The execution of MpCmdRun.exe with the `-RemoveDefinitions` argument is used to remove definitions from the Windows Malware Protection Engine, potentially indicating malware activity or attempts to bypass security measures.
date: "2024-01-09T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - endpoint
  - windows
vendors:
  - Microsoft
products:
  - Windows Defender
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://cert.gov.ua/article/6284730
rules:
  - title: Detect MpCmdRun RemoveDefinitions Execution
    description: Detects the execution of MpCmdRun.exe with the -RemoveDefinitions argument, used to remove Windows Defender definitions.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect MpCmdRun Execution from Unusual Location
    description: Detects MpCmdRun execution from a non-standard path, indicating potential masquerading.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may attempt to remove Windows Defender definitions to disable or impair the security product's capabilities and evade detection. This involves using the `MpCmdRun.exe` command-line tool, a legitimate Windows Defender utility, with the `-RemoveDefinitions` parameter. While administrators may use this functionality for legitimate purposes like testing, its presence can be an indicator of malicious activity, particularly when observed in conjunction with other suspicious behaviors. The detection focuses on identifying instances where `MpCmdRun.exe` is executed with the specific flag intended to remove definitions, potentially leaving the system vulnerable to malware infections. Identifying and responding to this activity is crucial to maintaining the integrity of endpoint security.

## Attack Chain

1.  Attacker gains initial access to the system (potentially through phishing or exploitation of a vulnerability).
2.  Attacker executes a malicious script or binary.
3.  The script or binary executes `MpCmdRun.exe` with the `-RemoveDefinitions` switch to remove existing malware definitions.
4.  `MpCmdRun.exe` processes the command and removes the current set of definitions used by Windows Defender.
5.  The system is now more vulnerable to malware as the definitions have been removed.
6.  The attacker proceeds with further malicious activities, such as lateral movement or data exfiltration, taking advantage of the weakened security posture.
7.  The attacker installs persistence mechanisms to maintain access.

## Impact

A successful attack that removes Windows Defender definitions can significantly impair an organization's defenses. Systems become vulnerable to malware infections that would otherwise be blocked. This can lead to data breaches, system compromise, and disruption of business operations. The impact ranges from individual workstation infections to widespread network compromise, depending on the attacker's objectives.

## Recommendation

*   Deploy the Sigma rule `Detect MpCmdRun RemoveDefinitions Execution` to your SIEM to detect the execution of `MpCmdRun.exe` with the `-RemoveDefinitions` argument.
*   Enable Sysmon process creation logging to collect the necessary event data for the Sigma rule to function.
*   Investigate any instances of `MpCmdRun.exe` being executed with `-RemoveDefinitions` to determine if it is a legitimate administrative action or malicious activity.
*   Tune the Sigma rule `Detect MpCmdRun RemoveDefinitions Execution` for your environment to reduce false positives, considering legitimate administrative use cases.
