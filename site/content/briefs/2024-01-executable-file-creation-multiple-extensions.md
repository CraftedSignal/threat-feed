---
title: Executable File Creation with Multiple Extensions
slug: 2024-01-executable-file-creation-multiple-extensions
description: Detection of executable files created with multiple extensions, a masquerading technique to evade defenses.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - execution
  - masquerading
  - windows
vendors:
  - Elastic
  - Microsoft
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - CrowdStrike
affected_os:
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
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_file_creation_mult_extension.toml
  - https://attack.mitre.org/techniques/T1036/
  - https://attack.mitre.org/techniques/T1036/007/
  - https://attack.mitre.org/techniques/T1204/
  - https://attack.mitre.org/techniques/T1204/002/
rules:
  - title: Executable File Creation with Multiple Extensions
    description: Detects the creation of executable files with multiple extensions, a technique used for masquerading.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.007
    data_sources:
      - file_event
      - windows
  - title: Suspicious Process Executing Double Extension File
    description: Detects a process executing a file with a double extension, indicative of masquerading.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1036.007
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Adversaries may use masquerading techniques to evade defenses and blend into the environment by manipulating the name or location of a file, tricking users into executing malicious code disguised as a benign file type. This rule detects the creation of executable files with multiple extensions, a common method of masquerading. The rule focuses on identifying suspicious file creations that use misleading extensions, specifically targeting files with an ".exe" extension preceded by common benign extensions. It excludes known legitimate processes to minimize false positives. This activity is relevant for defenders to identify potential threats where adversaries attempt to bypass security measures by disguising malicious files.

## Attack Chain

1.  An attacker crafts a malicious executable file with a double extension (e.g., "document.pdf.exe").
2.  The attacker delivers the malicious file to the target system via phishing or other means.
3.  The user downloads or receives the file and attempts to open it.
4.  Windows displays the file with the first extension ("document.pdf") by default, misleading the user.
5.  Upon execution, Windows recognizes the ".exe" extension and executes the file.
6.  The malicious executable runs, potentially deploying malware or performing other unauthorized actions.
7.  The malware establishes persistence or attempts lateral movement within the network.
8.  The attacker achieves their objective, such as data theft or system compromise.

## Impact

Successful exploitation can lead to malware infection, data breaches, and system compromise. This technique bypasses common file type restrictions and user awareness, potentially affecting a wide range of users and systems. While the number of victims is not specified, the impact can be significant, particularly in organizations where users handle sensitive data. The affected sectors are broad, encompassing any organization where users are susceptible to social engineering attacks.

## Recommendation

*   Deploy the Sigma rule "Executable File Creation with Multiple Extensions" to your SIEM and tune for your environment to detect the creation of suspicious files with multiple extensions.
*   Enable Sysmon Event ID 11 (File Create) for comprehensive file creation monitoring to improve the effectiveness of the detection rule.
*   Implement enhanced monitoring and logging for similar file creation activities to improve detection and response capabilities.
*   Educate users on the risks associated with double file extensions and encourage caution when opening attachments from unknown sources.
*   Review and whitelist legitimate software installations that may create executables with multiple extensions to reduce false positives, as described in the rule's triage notes.
