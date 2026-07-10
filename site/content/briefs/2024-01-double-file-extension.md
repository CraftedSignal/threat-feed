---
title: Executable File Creation with Multiple Extensions
slug: 2024-01-double-file-extension
description: This rule detects the creation of executable files with multiple extensions, a masquerading technique used to evade defenses by disguising malicious executables as benign files to trick users into executing them.
date: "2024-01-04T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - masquerading
  - file-extension
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://attack.mitre.org/techniques/T1036/
  - https://attack.mitre.org/techniques/T1036/007/
  - https://attack.mitre.org/techniques/T1204/
  - https://attack.mitre.org/techniques/T1204/002/
rules:
  - title: Executable File Creation with Multiple Extensions
    description: Detects the creation of executable files with multiple extensions, a common masquerading technique.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.007
    data_sources:
      - file_event
      - windows
  - title: Executable File Creation with Multiple Extensions - msiexec Exclusion
    description: Detects executable files with double extensions, excluding those created by msiexec to reduce false positives.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.007
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Adversaries may use masquerading techniques to evade defenses and blend in with the environment. One such technique involves manipulating the file extension of an executable file by appending multiple extensions. This is done to trick a user into executing what appears to be a benign file, such as a document or image, but is actually executable code. This technique, often referred to as "double file extension", can bypass security measures that rely on file extension filtering. This detection focuses on Windows environments and aims to identify suspicious file creations with misleading extensions, excluding known legitimate processes. The detection leverages file creation events and regular expression matching to identify potentially malicious files.

## Attack Chain

1.  User receives a file via email or downloads it from a website. The file has a double extension, such as "document.pdf.exe".
2.  The user, believing the file to be a PDF document, double-clicks the file to open it.
3.  Windows executes the file, treating it as an executable due to the ".exe" extension.
4.  The executable runs with the privileges of the user who launched it.
5.  The executable may download additional payloads or execute malicious commands.
6.  The malicious code performs actions such as installing malware, stealing credentials, or establishing persistence.
7.  The attacker gains control of the compromised system.

## Impact

A successful attack using this technique can lead to malware infection, data theft, and system compromise. The masquerading technique can bypass standard security measures, making it more likely that unsuspecting users will execute the malicious file. The impact can range from individual workstation compromise to broader network infections, potentially affecting numerous users and systems. This technique can lead to significant disruption of services and financial losses.

## Recommendation

*   Deploy the Sigma rule "Executable File Creation with Multiple Extensions" to your SIEM to detect the creation of files with suspicious double extensions (see rules).
*   Configure endpoint detection and response (EDR) systems to monitor file creation events and flag files with double extensions for further analysis (see rules).
*   Educate users about the risks of opening files with unusual or double extensions to prevent them from falling victim to this attack.
*   Review and harden email filtering policies to block or quarantine emails containing attachments with double extensions.
*   Implement application control policies to restrict the execution of unauthorized executables in user directories and temporary folders.
