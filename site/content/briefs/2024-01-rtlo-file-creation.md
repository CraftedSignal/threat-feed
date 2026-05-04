---
title: File with Right-to-Left Override Character (RTLO) Created/Executed
slug: 2024-01-rtlo-file-creation
description: This rule detects the creation or execution of files or processes with names containing the Right-to-Left Override (RTLO) character, which can be used to disguise the file extension and trick users into executing malicious files on Windows systems.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - rtlo
  - masquerading
  - windows
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
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
  - https://attack.mitre.org/techniques/T1036/
  - https://attack.mitre.org/techniques/T1036/002/
  - https://attack.mitre.org/techniques/T1204/
  - https://attack.mitre.org/techniques/T1204/002/
rules:
  - title: Detect RTLO Character in Filename
    description: Detects file creation events where the filename contains the RTLO character, indicating potential file masquerading.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.002
    data_sources:
      - file_event
      - windows
  - title: Detect RTLO Character in Process Name
    description: Detects process creation events where the process name contains the RTLO character.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Right-to-Left Override (RTLO) character (U+202E) is a Unicode character that causes text to be displayed from right to left, instead of the usual left to right. This character can be exploited by attackers to disguise malicious file extensions, making a harmful file appear safe to unsuspecting users. For example, an executable file named "evil.exe" could be renamed to "evilU+202Eegp.txt.exe," which, when displayed, would appear as "evil.exe.txt.ege," tricking the user into thinking it's a harmless text file. This detection rule identifies suspicious file or process activities on Windows systems by scanning for RTLO characters in file paths or process names, helping to uncover potential masquerading attempts. The detection is applicable to events from Elastic Defend, Microsoft Defender XDR, and SentinelOne Cloud Funnel.

## Attack Chain

1.  An attacker crafts a malicious file with an RTLO character embedded in its name. For example, `badU+202Eexe.txt`.
2.  The attacker delivers the malicious file to the target system, possibly through phishing, web downloads, or other social engineering techniques.
3.  The user receives the file and sees the file name as `bad.txt.exe` due to the RTLO character reversing the text display.
4.  The user, believing the file is a harmless text file, executes the file.
5.  The malicious file executes its intended payload, which could include installing malware, exfiltrating data, or performing other malicious actions.
6.  The executed process may attempt to establish a command and control (C2) connection with an external server to receive further instructions.
7.  The malware may attempt to escalate privileges or move laterally within the network to compromise additional systems.

## Impact

Successful exploitation can lead to the execution of arbitrary code on the victim's system. This can result in data theft, system compromise, and potential lateral movement within the network. The use of RTLO characters is a simple but effective defense evasion technique that can bypass standard security controls relying on file extension checks.

## Recommendation

*   Deploy the Sigma rule `Detect RTLO Character in Filename` to your SIEM to detect suspicious file creations and executions involving the RTLO character (Data Source: Sysmon).
*   Enable process monitoring with command line auditing to capture the execution of processes with RTLO characters in their names (Logsource: process_creation).
*   Educate users about the dangers of RTLO characters and the importance of verifying file extensions before execution.
*   Implement file extension filtering policies to block the execution of certain file types, regardless of the displayed file name.
