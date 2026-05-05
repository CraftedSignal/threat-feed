---
title: Windows File Association Modification via Ftype Command
slug: 2024-01-03-ftype-file-association
description: Adversaries can use the `ftype` command to modify Windows file associations, potentially redirecting legitimate file execution to malicious payloads for persistence, execution, and defense evasion.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - file-association
  - persistence
  - execution
  - windows
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_file_association_modification_via_ftype.yml
rules:
  - title: Detect File Association Modification via Ftype
    description: Detects the use of the `ftype` command to modify Windows file associations, potentially leading to malicious code execution.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
      - persistence
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
  - title: Detect File Association Modification via PowerShell
    description: Detects the use of the `ftype` command being called within a powershell script
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
      - persistence
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The `ftype` command is a Windows built-in utility that allows users to query and modify file type associations. While legitimate uses exist, adversaries can abuse this functionality to establish persistence, execute arbitrary code, and evade security controls. By modifying file associations, attackers can redirect the execution of legitimate file types (e.g., .txt, .doc, .exe) to malicious payloads. This can be used to maintain access to a compromised system even after a reboot or to bypass application whitelisting. This activity is often performed post-exploitation after an attacker has gained initial access to a system. Defenders should monitor for unauthorized or unexpected use of the `ftype` command to identify potential malicious activity. The original Splunk detection was published in 2026, indicating that the technique has been publicly known and detectable for some time.

## Attack Chain

1.  The attacker gains initial access to the system through exploitation or social engineering.
2.  The attacker executes an elevated command prompt or PowerShell session.
3.  The attacker uses the `ftype` command to query existing file associations to identify a suitable target.
4.  The attacker uses the `ftype` command to modify the file association of a targeted file extension (e.g., ".txt") to point to a malicious executable.
5.  A user double-clicks a file with the modified extension (e.g., a .txt file).
6.  Instead of opening in a text editor, the associated malicious executable is launched.
7.  The malicious executable performs its intended actions, such as installing malware, establishing persistence, or exfiltrating data.
8.  The attacker maintains persistence and control over the compromised system.

## Impact

Successful exploitation allows attackers to execute arbitrary code with the privileges of the user who opens the associated file. This can lead to the installation of malware, data theft, and further compromise of the network. The number of victims and sectors targeted depends on the attacker's objectives. If the attack succeeds, it can result in significant data breaches, financial losses, and reputational damage.

## Recommendation

*   Enable process creation logging with command line details for detection. This can be achieved through Sysmon or Windows Event Logging (Security Event ID 4688) (reference: Sysmon EventID 1, Windows Event Log Security 4688).
*   Deploy the Sigma rule `Detect File Association Modification via Ftype` to your SIEM and tune for your environment.
*   Monitor for processes executing from unusual locations or with unexpected command-line arguments after a file association modification event.
*   Implement application whitelisting to restrict the execution of unauthorized executables.
*   Review and audit existing file associations for any suspicious or unexpected configurations.
