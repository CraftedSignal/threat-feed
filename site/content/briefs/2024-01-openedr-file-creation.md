---
title: Suspicious File Creation via OpenEDR ITSMService
slug: 2024-01-openedr-file-creation
description: OpenEDR's ITSMService process, used for remote management, is being abused to create suspicious files on compromised systems, potentially leading to unauthorized file uploads, data staging, or malicious file deployment.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - openedr
  - itsmservice
  - file-creation
  - lateral-movement
vendors:
  - OpenEDR
products:
  - OpenEDR
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1570
    technique_name: Lateral Tool Transfer
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Remote File Copy
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
references:
  - https://kostas-ts.medium.com/detecting-abuse-of-openedrs-permissive-edr-trial-a-security-researcher-s-perspective-fc55bf53972c
rules:
  - title: Suspicious Executable File Creation by OpenEDR ITSMService
    description: Detects the creation of executable files by OpenEDR's ITSMService, which could indicate unauthorized activity.
    platform: sigma
    severity: high
    tactics:
      - execution
      - lateral_movement
    techniques:
      - T1218
      - T1570
    data_sources:
      - file_event
      - windows
  - title: Suspicious Script File Creation by OpenEDR ITSMService
    description: Detects the creation of script files (e.g., .ps1, .bat) by OpenEDR's ITSMService, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - lateral_movement
    techniques:
      - T1059.001
      - T1570
    data_sources:
      - file_event
      - windows
  - title: Compressed Archive Creation by OpenEDR ITSMService
    description: Detects the creation of compressed archive files by OpenEDR's ITSMService, potentially indicating data staging.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - file_event
      - windows
rules_count: 3
---

OpenEDR's ITSMService.exe is a legitimate component responsible for remote management operations within an environment. However, adversaries can abuse the ITSMService process to create executable or script files on the system through the process explorer or file management features. While these functions are legitimate for IT administrators, the creation of executable or script files in unusual locations or with suspicious names may indicate unauthorized file uploads, data staging for lateral movement, or the deployment of malicious payloads. This activity has been observed in experimental settings, highlighting the potential for abuse in real-world scenarios by threat actors aiming to leverage the built-in capabilities of OpenEDR for malicious purposes.

## Attack Chain

1.  Initial Access: An attacker gains initial access to the target system through external means (e.g., phishing, exploit).
2.  OpenEDR Access: The attacker gains control or access to an existing OpenEDR installation or is able to install/configure a rogue instance.
3.  ITSMService Exploitation: The attacker leverages the OpenEDR console to interact with the ITSMService.exe process.
4.  File Upload: The attacker uses the ITSMService to upload a malicious file (e.g., .exe, .dll, .ps1) to a location on the target system.
5.  Persistence (Optional): The attacker creates a scheduled task or modifies a registry key using ITSMService to maintain persistent access.
6.  Execution: The attacker leverages ITSMService to execute the uploaded malicious file.
7.  Lateral Movement: The executed payload initiates lateral movement, potentially using credentials obtained through OpenEDR or other tools.
8.  Objective: The attacker achieves their final objective, such as data exfiltration, ransomware deployment, or establishing a persistent backdoor.

## Impact

Successful exploitation allows attackers to bypass traditional security controls by abusing a trusted application (OpenEDR). It enables the deployment of malware, exfiltration of sensitive data, or the establishment of persistent access to compromised systems. While specific victim numbers are unknown, the permissive nature of OpenEDR's trial, as noted in research, suggests a broad potential attack surface. The impact could extend across various sectors utilizing OpenEDR for endpoint management.

## Recommendation

*   Deploy the Sigma rule "Potentially Suspicious File Creation by OpenEDR's ITSMService" to your SIEM to detect the creation of suspicious file types by the ITSMService process, and tune it for your environment.
*   Monitor file creation events for files with extensions like .exe, .dll, .ps1, .bat, etc. created by 'ITSMService.exe' (logsource: file_event/windows).
*   Implement strict access controls and auditing for OpenEDR consoles to prevent unauthorized use of ITSMService.exe.
*   Review and audit OpenEDR configurations to identify and remediate overly permissive settings.
