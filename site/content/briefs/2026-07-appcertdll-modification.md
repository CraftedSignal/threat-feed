---
title: Windows AppCertDLL Modification for Persistence and Privilege Escalation
slug: 2026-07-appcertdll-modification
description: Attackers can modify Windows AppCertDLL registry keys via command-line utilities to achieve persistence and privilege escalation by registering malicious DLLs to be loaded early in the system startup process.
date: "2026-07-27T18:22:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: This analytic detects attempts to modify AppCertDLL registry keys via some command line utility. Values under this key are used to specify DLLs loaded by the Windows Session Manager. Such modifications can be abused by attackers to load malicious code early in the system startup process, enabling persistent malware execution with high privileges.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546
    technique_name: Event Triggered Execution
    evidence: Values under this key are used to specify DLLs loaded by the Windows Session Manager. Such modifications can be abused by attackers to load malicious code early in the system startup process, enabling persistent malware execution with high privileges.
    confidence_band: high
references:
  - https://www.hexacorn.com/blog/2013/01/19/beyond-good-ol-run-key-part-3/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_appcertdll_modification_via_command_line.yml
rules:
  - title: Detect AppCertDLL Modification via Command Line
    description: Detects attempts to modify AppCertDLL registry keys via command-line utilities, indicating a potential persistence or privilege escalation attempt.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1546.009
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

This threat involves the modification of specific Windows registry keys related to AppCertDLLs (Application Certification DLLs) to achieve persistence and privilege escalation. Attackers utilize command-line utilities to alter values under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs`, which are typically used by the Windows Session Manager to specify DLLs loaded during the system startup process. By registering a malicious DLL in this location, adversaries can ensure their code executes with high privileges very early in the system boot sequence, making it a potent technique for maintaining control and bypassing security measures. This method is effective for sustained access to compromised systems and can lead to full system takeover.

## Attack Chain

1. Attacker gains initial access to a Windows system through various means (e.g., exploitation, phishing, credential compromise).
2. The attacker executes a command-line utility (e.g., `reg.exe`, `powershell.exe`) with administrative privileges.
3. The utility modifies values under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs`.
4. A path to a malicious DLL is registered within the `AppCertDLLs` key.
5. Upon subsequent system startup or specific process creation, the Windows Session Manager attempts to load the DLLs specified in this registry location.
6. The malicious DLL is loaded, granting the attacker persistent execution with System-level privileges, enabling further compromise or data exfiltration.

## Impact

Successful exploitation of this technique grants attackers persistent access to the compromised system with elevated privileges (System). This can lead to a full system compromise, allowing adversaries to install additional malware, exfiltrate sensitive data, disable security software, or establish further footholds. The early loading of malicious code makes it difficult for traditional security solutions to detect and prevent, enhancing the attacker's ability to evade defenses and maintain a covert presence.

## Recommendation

* Deploy the Sigma rule "Detect AppCertDLL Modification via Command Line" to your SIEM and tune for your environment.
* Ensure Sysmon Event ID 1 (Process Creation) and Windows Event Log Security 4688 are collected from all Windows endpoints to enable detection.
* Regularly review modifications to the `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs` registry key, especially when initiated by unusual processes.
