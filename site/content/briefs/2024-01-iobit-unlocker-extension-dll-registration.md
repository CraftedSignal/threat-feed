---
title: IOBit Unlocker Extension DLL Registration via Regsvr32
slug: 2024-01-iobit-unlocker-extension-dll-registration
description: The IOBit Unlocker Extension DLL is being registered via regsvr32.exe, a Windows utility used to unlock files or folders by terminating locking processes, which could be abused for malicious purposes.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - iobit
  - unlocker
  - regsvr32
  - dll
  - windows
  - threat-detection
vendors:
  - IObit
  - Splunk
products:
  - Unlocker Extension
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://thedfirreport.com/2024/04/01/from-onenote-to-ransomnote-an-ice-cold-intrusion/
rules:
  - title: Detect IOBit Unlocker Extension DLL Registration via Regsvr32
    description: Detects the registration of IOBit Unlocker Extension DLL using regsvr32.exe
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.010
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Regsvr32 Usage
    description: Detects regsvr32.exe registering DLLs from unusual directories.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1218.010
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

IOBit Unlocker is a legitimate Windows utility designed to resolve issues involving files or folders that cannot be deleted, moved, or renamed because they are locked by other processes or applications. Attackers can abuse this tool by registering a malicious extension DLL that enables them to unlock and manipulate critical system files, potentially leading to privilege escalation, data exfiltration, or system compromise. This technique can be employed to disable security software, modify system configurations, or deploy malware more effectively.

## Attack Chain

1. An attacker gains initial access to a compromised system.
2. The attacker drops a malicious DLL file, disguised as or named similarly to "IObitUnlockerExtension.dll", onto the system.
3. The attacker uses regsvr32.exe to register the malicious DLL: `regsvr32.exe /s IObitUnlockerExtension.dll`. The `/s` flag is used for silent registration to avoid user interaction.
4. Upon successful registration, the DLL is loaded by the system.
5. The malicious DLL hooks into system processes, granting the attacker the ability to unlock files and folders protected by the operating system or other applications.
6. The attacker leverages the DLL's capabilities to unlock files or folders related to security software, such as antivirus programs, or critical system configurations.
7. The attacker modifies or replaces these unlocked files to disable security controls, escalate privileges, or plant persistent malware.
8. The attacker achieves their objective, which may include data exfiltration, system disruption, or deploying ransomware.

## Impact

Successful exploitation can lead to the complete compromise of a Windows host. An attacker may disable security software, modify sensitive system configurations, and deploy malware undetected. The DFIR Report has observed this technique used in intrusions leading to ransomware deployment.

## Recommendation

*   Deploy the Sigma rule `Detect IOBit Unlocker Extension DLL Registration via Regsvr32` to your SIEM to identify suspicious registrations of IOBitUnlockerExtension.dll.
*   Monitor process creation events for instances of `regsvr32.exe` registering DLLs from unusual or suspicious locations.
*   Implement application control policies to restrict the execution of `regsvr32.exe` to authorized users and processes.
*   Regularly review and audit registered DLLs to identify any unauthorized or malicious extensions.
*   Investigate any endpoint activity involving IObit Unlocker, including file modifications and process terminations related to locked files.
