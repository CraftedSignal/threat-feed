---
title: Registry Persistence via AppCert DLL
slug: 2024-01-appcert-dll-persistence
description: Detection of Registry Persistence via AppCert DLL, which involves modifying registry keys to load malicious DLLs upon process creation, enabling persistence and potential privilege escalation.
date: "2024-01-03T14:22:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546
    technique_name: Event Triggered Execution
references:
  - https://attack.mitre.org/techniques/T1546/
  - https://attack.mitre.org/techniques/T1546/009/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/persistence_appcertdlls_registry.toml
rules:
  - title: Registry Persistence via AppCert DLL Modification
    description: Detects modification of the AppCertDLLs registry key to add a new DLL path, indicating a potential persistence mechanism.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1546.009
    data_sources:
      - registry_set
      - windows
  - title: Process Loading Newly Registered AppCert DLL
    description: Detects a process loading a DLL that was recently added to the AppCertDLLs registry key.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1546.009
    data_sources:
      - image_load
      - windows
rules_count: 2
---

This detection identifies attempts to establish persistence on Windows systems by manipulating the AppCert DLLs registry keys. AppCert DLLs are loaded by every process that uses standard Windows API calls for process creation. Adversaries can exploit this mechanism by modifying the registry to include paths to malicious DLLs, ensuring these DLLs are loaded into every newly created process. This technique, often associated with persistence and privilege escalation, allows for stealthy execution of malicious code across system reboots. The targeted registry paths include `HKLM\SYSTEM\ControlSet*\Control\Session Manager\AppCertDLLs\*`. This activity is detected via event logs that record registry modifications. The rule was last updated on 2026/04/07.

## Attack Chain

1.  An attacker gains initial access to the system via various means (e.g., exploiting a vulnerability or using compromised credentials).
2.  The attacker obtains elevated privileges on the system to modify critical registry keys.
3.  The attacker modifies the `HKLM\SYSTEM\ControlSet*\Control\Session Manager\AppCertDLLs\*` registry key to include a path to a malicious DLL.
4.  The malicious DLL is placed on the system, potentially disguised as a legitimate system file.
5.  A new process is created using standard Windows API calls.
6.  The operating system loads the DLLs listed in the `AppCertDLLs` registry key into the newly created process.
7.  The malicious DLL executes its payload within the context of the newly created process, allowing the attacker to perform malicious actions.
8.  This process repeats for every new process created on the system, ensuring persistence across reboots.

## Impact

Successful exploitation allows attackers to achieve persistent code execution, enabling them to maintain control over the compromised system. This can lead to data theft, further malware deployment, or complete system compromise. The impact ranges from minor disruptions to significant data breaches and system unavailability. The risk score associated with this activity is 47.

## Recommendation

*   Deploy the Sigma rule "Registry Persistence via AppCert DLL" to your SIEM to detect modifications to the `AppCertDLLs` registry key.
*   Enable Sysmon registry event logging to capture changes to the targeted registry paths for accurate detection.
*   Implement strict registry permission controls to limit who can modify the `AppCertDLLs` registry key.
*   Regularly audit the `AppCertDLLs` registry key for unauthorized modifications.
*   Use endpoint detection and response (EDR) tools to monitor and block suspicious DLLs being loaded by processes.
*   Review and whitelist legitimate software that modifies the `AppCertDLLs` registry key to reduce false positives, as noted in the rule description.
