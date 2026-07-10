---
title: Right-to-Left Override (RTLO) Masquerading
slug: 2024-01-rtlo-masquerading
description: Adversaries use the Right-to-Left Override (RTLO) character in filenames to disguise malicious files and trick users into executing them, leading to potential malware infection and system compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - masquerading
  - rtlo
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
  - https://attack.mitre.org/techniques/T1036/002/
  - https://attack.mitre.org/techniques/T1204/
  - https://attack.mitre.org/techniques/T1204/002/
rules:
  - title: File Creation with Right-to-Left Override Character (RTLO)
    description: Detects creation of files with names containing the Right-to-Left Override (RTLO) character.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.002
    data_sources:
      - file_event
      - windows
  - title: Process Execution with Right-to-Left Override Character (RTLO)
    description: Detects execution of processes with names containing the Right-to-Left Override (RTLO) character.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.002
    data_sources:
      - process_creation
      - windows
  - title: Process Command Line with Right-to-Left Override Character (RTLO)
    description: Detects process execution with command line containing the Right-to-Left Override (RTLO) character.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.002
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

The Right-to-Left Override (RTLO) character (U+202E) is a Unicode character that reverses the display order of text. Attackers exploit this character in filenames to disguise malicious executables, making them appear as benign file types (e.g., `evil.pdf.exe` displayed as `evil.exe.pdf`). This technique, known as RTLO masquerading, aims to deceive users into executing malware. This activity has been observed across various threat actors and campaigns, targeting Windows systems primarily. Detection of RTLO character usage is critical to preventing user execution of malicious payloads. This behavior has been observed as early as 2015 and continues to be relevant as of 2024.

## Attack Chain

1. The attacker crafts a malicious executable with a filename containing the RTLO character (e.g., `evil.fdp.exe`).
2. The attacker distributes the disguised file via a phishing email or compromised website.
3. The user receives the file and, due to the RTLO character, sees the filename as `evil.exe.fdp`, mistaking it for a PDF document.
4. The user double-clicks the disguised file, initiating its execution.
5. The malicious executable runs with the user's privileges.
6. The malware performs malicious actions, such as installing backdoors, stealing data, or encrypting files.

## Impact

Successful exploitation leads to the execution of arbitrary code on the victim's machine, potentially resulting in data theft, system compromise, or ransomware infection. The impact can range from individual system infections to widespread organizational breaches. While precise victim counts are difficult to ascertain, RTLO masquerading remains a common social engineering tactic, affecting numerous users across various sectors.

## Recommendation

*   Deploy the Sigma rule "File with Right-to-Left Override Character (RTLO) Created/Executed" to your SIEM and tune for your environment, focusing on `file.path` and `process.name` fields.
*   Enable Sysmon process-creation and file-creation logging to provide the necessary data for the Sigma rule to function effectively.
*   Educate users about the dangers of RTLO masquerading and encourage them to be cautious when opening files, especially those with unusual or reversed filenames.
