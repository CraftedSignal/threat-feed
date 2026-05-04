---
title: Potential Defense Evasion via Filter Manager (fltMC.exe)
slug: 2024-01-filter-manager-evasion
description: Adversaries may abuse the Filter Manager Control Program (fltMC.exe) to unload filter drivers, thereby evading security software defenses such as malware detection and file system monitoring.
date: "2024-01-03T14:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - filter-driver
  - fltMC.exe
  - windows
vendors:
  - Microsoft
  - ManageEngine
  - Bitdefender
  - SentinelOne
products:
  - Defender XDR
  - Endpoint Security
  - UEMS_Agent
  - SentinelOne Cloud Funnel
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/001/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_via_filter_manager.toml
rules:
  - title: Potential Evasion via Filter Manager
    description: Detects attempts to unload filter drivers using fltMC.exe, potentially evading security defenses.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: FltMC.exe Executed from Suspicious Process
    description: Detects fltMC.exe executed from unusual processes that may indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Filter Manager Control Program (fltMC.exe) is a Windows utility used to manage filter drivers, also known as minifilters. These minifilters are leveraged by various security products, including EDR, antivirus solutions, and data loss prevention tools, to intercept and modify I/O requests. Attackers can abuse fltMC.exe to unload these minifilters, effectively disabling or circumventing the security measures they provide. This allows malicious actors to operate without detection, potentially leading to data breaches, malware infections, or other harmful activities. This technique has been observed being used to disable security products such as Bitdefender, SentinelOne and ManageEngine Endpoint Central.

## Attack Chain

1.  Attacker gains initial access to the target system (e.g., via compromised credentials or exploit).
2.  Attacker executes `fltMC.exe` with administrative privileges.
3.  `fltMC.exe` attempts to unload a specific filter driver (minifilter).
4.  The operating system processes the request to unload the specified filter driver.
5.  If successful, the targeted minifilter is removed from the active filter stack.
6.  Security software relying on the unloaded minifilter ceases to function correctly, leaving a security gap.
7.  Attacker performs malicious actions, such as deploying malware or exfiltrating sensitive data, without the protection of the disabled filter driver.
8.  Attacker achieves their objective, such as data theft or system compromise.

## Impact

Successful exploitation allows attackers to disable or circumvent security controls, increasing the likelihood of successful malware infections, data breaches, and other malicious activities. The scope of impact depends on the specific filter driver unloaded and the security products it supports. Disabling a critical EDR minifilter could leave the entire system vulnerable, while disabling a less critical filter might only impact a subset of security features.

## Recommendation

*   Monitor process creation events for the execution of `fltMC.exe` with the `unload` argument to identify potential evasion attempts (see Sigma rule "Potential Evasion via Filter Manager").
*   Investigate any instances of `fltMC.exe` execution where the parent process is not a known and trusted system management tool.
*   Implement strict access controls to limit the ability of users to execute `fltMC.exe` or modify filter driver configurations.
*   Review the list of exclusions in the provided EQL query to identify any legitimate software that may be generating false positives.
*   Ensure that endpoint security solutions are properly configured and monitored to detect and prevent unauthorized filter driver modifications.
*   Enable Sysmon process creation logging to activate the rules above.
