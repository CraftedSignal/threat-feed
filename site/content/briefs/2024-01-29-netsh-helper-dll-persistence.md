---
title: Netsh Helper DLL Persistence via Registry Modification
slug: 2024-01-29-netsh-helper-dll-persistence
description: Attackers may establish persistence by adding a malicious DLL as a Netsh Helper, which executes whenever the Netsh utility is run, often abusing this mechanism to execute malicious payloads.
date: "2024-01-29T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - registry
  - netsh
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
references:
  - https://attack.mitre.org/techniques/T1546/
  - https://attack.mitre.org/techniques/T1546/007/
  - https://attack.mitre.org/techniques/T1112/
rules:
  - title: Netsh Helper DLL Registry Modification
    description: Detects modification of the Netsh Helper DLL registry keys.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1112
      - T1546.007
    data_sources:
      - registry_set
      - windows
  - title: Netsh Execution with Suspicious Arguments
    description: Detects netsh.exe execution with arguments indicative of malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1546.007
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Windows Netsh utility (netsh.exe) is a command-line tool used for configuring and managing network settings. It supports extensibility through Netsh Helper DLLs, which can be added to extend its functionality. Attackers can abuse this mechanism by adding malicious DLLs to execute arbitrary code whenever netsh.exe is executed. This can be done by legitimate administrators or via scheduled tasks. The registry keys associated with Netsh Helper DLLs are a known persistence location. This activity matters to defenders because it allows attackers to establish a persistent foothold on a compromised system, potentially leading to further malicious activities.

## Attack Chain

1. An attacker gains initial access to a Windows system (e.g., via phishing or exploiting a vulnerability).
2. The attacker obtains necessary privileges to modify the registry.
3. The attacker crafts a malicious DLL file to be used as a Netsh Helper.
4. The attacker modifies the Windows Registry to add an entry under `HKLM\Software\Microsoft\netsh\` pointing to the malicious DLL.
5. The attacker, or a legitimate administrator, executes `netsh.exe`.
6. Upon execution, `netsh.exe` loads the malicious DLL specified in the registry.
7. The malicious DLL executes its payload, achieving the attacker's objective.
8. This execution persists across reboots and user logons, as `netsh.exe` is commonly used by administrators and scheduled tasks.

## Impact

A successful attack leveraging Netsh Helper DLL persistence allows attackers to execute arbitrary code on a compromised system. This can lead to a variety of malicious activities, including data theft, installation of malware, or further propagation within the network. While the risk score is low, the persistence mechanism makes it valuable to attackers.

## Recommendation

*   Enable Sysmon process-creation logging to capture `netsh.exe` executions and correlate with registry modifications (see rule below).
*   Deploy the Sigma rule "Netsh Helper DLL Registry Modification" to your SIEM and tune for your environment.
*   Implement enhanced monitoring and logging for registry changes related to Netsh Helper DLLs.
