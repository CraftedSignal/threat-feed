---
title: Potential Persistence via Time Provider Modification
slug: 2024-01-time-provider-modification
description: Adversaries may establish persistence by registering and enabling a malicious DLL as a time provider by modifying registry keys associated with the W32Time service.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - time-provider
vendors:
  - Microsoft
  - VMware
products:
  - Windows
  - VMware Tools
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://pentestlab.blog/2019/10/22/persistence-time-providers/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_time_provider_mod.toml
rules:
  - title: Time Provider DLL Registration
    description: Detects the registration of a new DLL file as a Time Provider in the Windows Registry.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.003
    data_sources:
      - registry_set
      - windows
  - title: Time Provider Modification via msiexec
    description: Detects modification of Time Provider settings via msiexec.exe, which may indicate malicious or legitimate software installation.
    platform: sigma
    severity: informational
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.003
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

The Windows Time service (W32Time) synchronizes the system clock with other devices on the network, using time providers implemented as DLL files located in the System32 folder. This architecture can be abused by adversaries to establish persistence by registering and enabling a malicious DLL as a time provider. The W32Time service starts during Windows startup and loads w32time.dll. This technique involves modifying specific registry keys associated with the Time Providers, enabling a malicious DLL to be loaded and executed every time the service starts. This can allow an attacker to maintain persistent access to the system, even after a reboot. The Elastic Security team has identified this persistence method and provided a detection rule to identify such modifications.

## Attack Chain

1.  The attacker gains initial access to the system through an exploit, phishing, or other means.
2.  The attacker obtains administrator privileges on the target system.
3.  The attacker crafts or deploys a malicious DLL to be used as a time provider.
4.  The attacker modifies the registry to register the malicious DLL as a valid time provider. The registry keys under `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\` are targeted.
5.  The attacker enables the newly registered time provider.
6.  The W32Time service is restarted, or the system is rebooted.
7.  The W32Time service loads the malicious DLL, executing the attacker's code.
8.  The attacker maintains persistent access to the compromised system.

## Impact

Successful exploitation allows the attacker to achieve persistence on the compromised system. The attacker can execute arbitrary code every time the W32Time service starts. This may lead to further malicious activities, such as data theft, lateral movement, or the installation of additional malware. The impact is significant, as the attacker can maintain long-term control over the system.

## Recommendation

*   Deploy the Sigma rule `Time Provider DLL Registration` to detect the registration of new DLL files as Time Providers in the registry.
*   Enable Sysmon registry event logging to capture registry modifications, as this is a requirement for the provided Sigma rules.
*   Investigate any registry changes to the `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\` path, especially those adding new DLLs, using the provided Sigma rule.
*   Monitor process execution for `msiexec.exe` installing DLLs in the `Program Files\VMware\VMware Tools` directory, which could indicate legitimate activity, but should still be validated.
*   Regularly audit and validate the list of registered Time Providers on critical systems.
