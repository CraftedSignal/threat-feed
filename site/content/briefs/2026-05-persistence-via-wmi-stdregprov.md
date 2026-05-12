---
title: Persistence via WMI Standard Registry Provider
slug: 2026-05-persistence-via-wmi-stdregprov
description: The rule identifies the use of Windows Management Instrumentation StdRegProv (registry provider) to modify commonly abused registry locations for persistence by detecting registry changes made by WmiPrvSe.exe in specific registry paths.
date: "2026-05-12T18:59:41Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - persistence
  - registry
  - wmi
  - windows
vendors:
  - Microsoft
products:
  - Windows Management Instrumentation
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://learn.microsoft.com/en-us/previous-versions/windows/desktop/regprov/stdregprov
  - https://www.elastic.co/security-labs/hunting-for-persistence-using-elastic-security-part-1
rules:
  - title: Detect WMI Registry Persistence via Run Keys
    description: Detects persistence via WMI StdRegProv modification of Run keys in the registry.  Alerts when WmiPrvSe.exe modifies specific registry paths related to autorun.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
  - title: Detect WMI Registry Persistence via Service ImagePath Modification
    description: Detects persistence via WMI StdRegProv modification of the Service ImagePath registry key. Alerts when WmiPrvSe.exe modifies the ImagePath of a service.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.003
    data_sources:
      - registry_set
      - windows
  - title: Detect WMI Registry Persistence via Winlogon Shell Modification
    description: Detects persistence via WMI StdRegProv modification of the Winlogon Shell registry key.  Alerts when WmiPrvSe.exe modifies the Winlogon Shell key.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1069.001
    data_sources:
      - registry_set
      - windows
rules_count: 3
---

This detection rule identifies the abuse of the Windows Management Instrumentation (WMI) StdRegProv, specifically `WmiPrvSe.exe`, to establish persistence on a Windows system. Attackers can leverage WMI's registry provider to modify sensitive registry keys related to autostart execution points (ASEPs) without directly spawning child processes. The rule focuses on detecting registry modifications in locations such as `HKEY_USERS`, `HKLM`, and `\\REGISTRY` associated with Run keys, RunOnce keys, service configurations, and other persistence mechanisms. The rule aims to detect malicious modifications introduced via WMI rather than through direct registry manipulation. This technique allows attackers to maintain system access even after a reboot or user logon, making it a valuable indicator of compromise for defenders. The rule was last updated on 2026/05/03.

## Attack Chain

1.  Attacker gains initial access to the system, possibly through exploiting a vulnerability or using stolen credentials.
2.  Attacker leverages WMI to interact with the `StdRegProv` class, a WMI provider for registry operations.
3.  Attacker uses the `CreateKey` or `SetStringValue` methods within `StdRegProv` to modify critical registry locations related to persistence.
4.  The registry modifications are performed by the `WmiPrvSe.exe` process, the WMI provider host.
5.  The attacker targets registry keys such as `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run` to execute a payload upon system startup.
6.  The attacker also modifies service-related registry keys such as `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\ImagePath` to execute a malicious DLL or executable as a service.
7.  Upon system restart or user logon, the modified registry keys trigger the execution of the attacker's payload.
8.  The attacker achieves persistence on the system, allowing them to maintain access and perform further malicious activities.

## Impact

Successful exploitation leads to persistent access on the compromised system. This allows attackers to maintain a foothold even after reboots, enabling them to perform activities such as data theft, lateral movement, and further malware deployment. If widespread, this can result in significant disruption and data loss across the organization. The risk score of this rule is 73, indicating a significant potential impact.

## Recommendation

*   Enable and monitor registry event logging, specifically focusing on changes made to the registry paths outlined in the rule query, to improve detection capabilities.
*   Investigate any registry modifications made by `WmiPrvSe.exe` to the registry paths in the query, prioritizing those with unusual or suspicious data, as highlighted in the investigation guide.
*   Deploy the Sigma rule "Persistence via WMI Standard Registry Provider" to your SIEM to detect suspicious WMI-based registry modifications.
*   Monitor process creations originating from the registry keys modified by `WmiPrvSe.exe` to identify potential payload execution.
*   Review the references provided for additional context on the StdRegProv class and hunting for persistence using Elastic Security.
