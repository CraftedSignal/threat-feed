---
title: Component Object Model (COM) Hijacking via Registry Modification
slug: 2024-01-com-hijacking
description: Adversaries may establish persistence by executing malicious content triggered by hijacked references to COM objects through Component Object Model (COM) hijacking via registry modification on Windows systems.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - com-hijacking
  - windows
  - registry
  - defense-evasion
  - privilege-escalation
vendors:
  - Elastic
  - Island Technology Inc.
  - Google LLC
  - Grammarly, Inc.
  - Dropbox, Inc.
  - REFINITIV US LLC
  - HP Inc.
  - Adobe Inc.
  - Citrix Systems, Inc.
  - Veeam Software Group GmbH
  - Zhuhai Kingsoft Office Software Co., Ltd.
  - Oracle America, Inc.
  - Brave Software, Inc.
  - DeepL SE
  - Opera Norway AS
  - Slack Technologies, LLC
  - Spotify AB
  - Vivaldi Technologies AS
  - Microsoft
products:
  - Elastic Defend
  - OneDrive.exe
  - OneDriveSetup.exe
  - FileSyncConfig.exe
  - Teams.exe
  - MicrosoftEdgeUpdate.exe
  - msrdcw.exe
  - MicrosoftEdgeUpdateComRegisterShell64.exe
  - setup.exe
  - PowerToys.PowerLauncher.exe
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1112
    technique_name: Modify Registry
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_suspicious_com_hijack_registry.toml
  - https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/
rules:
  - title: Suspicious COM Hijack Registry Modification
    description: Detects suspicious modifications to COM object registry keys that may indicate COM hijacking attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
      - privilege_escalation
    techniques:
      - T1112
      - T1546.015
    data_sources:
      - registry_set
      - windows
  - title: Suspicious COM Hijack Registry Modification - User Hive
    description: Detects suspicious modifications to COM object registry keys under the HKEY_USERS hive.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
      - privilege_escalation
    techniques:
      - T1112
      - T1546.015
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Component Object Model (COM) hijacking is a persistence and privilege escalation technique used by adversaries to execute malicious code by hijacking references to COM objects. This involves modifying specific registry keys to redirect COM object instantiation to attacker-controlled DLLs or executables. The technique is difficult to detect due to the legitimate use of COM objects by various applications and the operating system itself. This brief focuses on identifying suspicious registry modifications indicative of COM hijacking, while excluding known legitimate processes to minimize false positives. The original Elastic detection rule was published in November 2020 and last updated in May 2026, showcasing its continued relevance. This activity matters to defenders because successful COM hijacking allows attackers to execute arbitrary code with the privileges of the user or service that instantiates the hijacked COM object.

## Attack Chain

1.  The attacker gains initial access to the system (e.g., through phishing or exploiting a vulnerability).
2.  The attacker identifies a target COM object to hijack by enumerating COM object entries in the registry.
3.  The attacker modifies the `InprocServer32` or `LocalServer32` registry keys associated with the target COM object to point to a malicious DLL or executable.
4.  The attacker may also modify the `DelegateExecute` registry key to control how the COM object is executed.
5.  A legitimate application or service attempts to instantiate the original COM object.
6.  Due to the registry modifications, the malicious DLL or executable is loaded and executed instead.
7.  The malicious code performs its intended actions, such as establishing persistence, escalating privileges, or executing arbitrary commands.
8.  The attacker maintains persistent access to the system and potentially gains elevated privileges through the hijacked COM object.

## Impact

Successful COM hijacking enables attackers to establish persistent access to compromised systems and potentially escalate privileges. The impact can range from executing arbitrary code with user privileges to gaining system-level access, depending on the context in which the hijacked COM object is used. The Elastic detection rule aims to identify and prevent such attacks by detecting suspicious registry modifications, but the overall number of affected systems or specific sectors targeted by this technique are not specified in the original source.

## Recommendation

*   Enable Windows Registry auditing to capture registry modification events and activate the Sigma rule `Suspicious COM Hijack Registry Modification` to detect potential COM hijacking attempts.
*   Investigate any alerts generated by the Sigma rule, focusing on processes modifying COM-related registry keys and their associated executables.
*   Implement code signing validation and monitor for unsigned or unexpected DLLs being loaded by legitimate processes, as indicated in the rule's description.
*   Regularly review and update the list of excluded processes and trusted code signers in the Sigma rule to minimize false positives.
*   Deploy the EQL rule provided by Elastic, adjusting the `from` and `index` fields to match your environment, and tune the process and signature exclusions for your environment.
*   Monitor for registry changes in `HKEY_USERS` hive related to COM objects, as these are considered less common and potentially malicious.
