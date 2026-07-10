---
title: Persistence via Malicious Microsoft Office Add-ins
slug: 2024-01-31-office-addins-persistence
description: Attackers can establish persistence by placing malicious add-ins (e.g., .xll, .xlam) in Microsoft Office startup directories, ensuring execution each time the application launches.
date: "2024-01-31T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - office-addins
  - windows
vendors:
  - Microsoft
products:
  - Microsoft Office
  - Word
  - Excel
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1137
    technique_name: Office Application Startup
references:
  - https://labs.withsecure.com/publications/add-in-opportunities-for-office-persistence
  - https://attack.mitre.org/techniques/T1137/
  - https://attack.mitre.org/techniques/T1137/006/
  - https://attack.mitre.org/tactics/TA0003/
rules:
  - title: Detect Suspicious Office Add-in Creation in Startup Directories
    description: Detects the creation of suspicious Office add-in files (e.g., .xll, .xlam) in the Microsoft Office startup directories.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1137.006
    data_sources:
      - file_event
      - windows
  - title: Detect Office Application Loading Suspicious Add-ins
    description: Detects Microsoft Office applications loading add-ins from suspicious locations.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1137.006
    data_sources:
      - image_load
      - windows
rules_count: 2
---

Attackers can abuse Microsoft Office add-ins to establish persistence on compromised Windows systems. This involves placing malicious files with extensions like `.xll`, `.xla`, or `.xlam` into specific Microsoft Office startup directories. When Office applications like Word or Excel are launched, these add-ins are automatically loaded, providing a means for the attacker to execute arbitrary code. This technique allows the attacker to maintain a persistent presence on the system, even after reboots or user logoffs. The targeted directories include "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Word\\Startup\\", "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\AddIns\\", and "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Excel\\XLSTART\\". This threat matters because it enables long-term access and control over the compromised system, potentially leading to data theft, further network intrusion, or other malicious activities.

## Attack Chain

1.  The attacker gains initial access to the system through an unknown vector (e.g., compromised credentials, or prior malware infection).
2.  The attacker identifies the Microsoft Office installation and its associated add-in directories.
3.  The attacker crafts a malicious Office add-in with a file extension such as `.xll`, `.xla`, or `.xlam`. This add-in contains malicious code designed to execute upon loading.
4.  The attacker places the malicious add-in file into one of the Microsoft Office startup directories (e.g., "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Word\\Startup\\").
5.  The victim launches a Microsoft Office application (e.g., Word, Excel).
6.  The Office application automatically loads the add-in from the startup directory.
7.  The malicious code within the add-in executes, providing the attacker with code execution capabilities on the system.
8.  The attacker maintains persistent access to the system, enabling them to perform actions such as data exfiltration or lateral movement.

## Impact

Successful exploitation allows attackers to establish persistence on the compromised system. This can lead to unauthorized access to sensitive data, further propagation within the network, and deployment of additional malware. The number of victims and the specific sectors targeted can vary depending on the attacker's objectives and the compromised organization's profile. If the attack succeeds, the organization may suffer significant financial losses, reputational damage, and legal liabilities.

## Recommendation

*   Enable Sysmon file creation logging to monitor the creation of files in the Microsoft Office startup directories to activate the rules below.
*   Deploy the Sigma rules in this brief to your SIEM to detect the creation of suspicious Office add-in files.
*   Regularly scan systems for malicious Office add-ins using endpoint detection and response (EDR) solutions.
*   Implement application control policies to restrict the execution of unauthorized Office add-ins.
*   Educate users about the risks associated with untrusted Office add-ins and encourage them to only install add-ins from trusted sources.
*   Monitor network traffic for suspicious activity originating from systems with newly created Office add-ins.
