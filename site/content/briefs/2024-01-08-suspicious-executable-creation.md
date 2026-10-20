---
brief_id: brief-2024-01-08-suspicious-executable-creation
event_id: brief-2024-01-08-suspicious-executable-creation
revision: 2
activity_at: "2024-01-08T12:00:00Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:e0eed5df25b402f75ad5ee0cd0f18a7705fc87ebf71c1bb35e5a957ddf58b0ca
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Executable or Script Creation in Suspicious Paths
slug: 2024-01-08-suspicious-executable-creation
description: Attackers may create executables or scripts in suspicious directories to establish persistence, execute malicious code, or evade detection by blending in with legitimate system activity.
date: "2024-01-08T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
tags:
  - persistence
  - suspicious-file-creation
  - endpoint
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/executables_or_script_creation_in_suspicious_path.yml
rules:
  - title: Executable Created in Public User Directory
    description: Detects the creation of executable files (.exe, .dll) in the Public user directory, which is often abused by attackers.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - file_event
      - windows
  - title: Script Created in AppData Directory
    description: Detects the creation of script files (.ps1, .bat, .vbs) in the AppData directory, a common location for malware persistence.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - file_event
      - windows
  - title: Executable Created in Windows Temp Directory
    description: Detects creation of executable files in the Windows Temp directory.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - file_event
      - windows
rules_count: 3
---

Attackers often create executable files (e.g., .exe, .dll, .ps1, .py) in unusual directories as part of their attack operations. This can be a way to establish persistence by placing a malicious script in a startup folder, or it could be a way to execute code while avoiding detection. Standard user directories like AppData, Temp, or Public are common targets because they often have relaxed security controls and are less scrutinized than system directories. This technique allows malicious actors to blend in with normal user activity. This type of behavior can be seen across various attack campaigns, from commodity malware to advanced persistent threats (APTs). Detecting these file creations is crucial for identifying compromised systems.

## Attack Chain

1.  Initial Access: The attacker gains initial access through an exploit or social engineering.
2.  Privilege Escalation: The attacker escalates privileges to gain higher-level access to the system.
3.  Payload Delivery: The attacker downloads a malicious payload, often a script or executable.
4.  Suspicious Directory Creation: The attacker creates a new directory or uses an existing one in a suspicious location like `C:\Users\Public\`, `C:\Windows\Temp\`, or `%AppData%`.
5.  Executable/Script Creation: The attacker writes the malicious payload (e.g., a PowerShell script, batch file, or compiled executable) to the created or existing directory.
6.  Persistence: The attacker creates a scheduled task or modifies a registry key to execute the malicious script or executable automatically on system startup or user login.
7.  Command and Control: The malicious script or executable establishes a connection to a command-and-control server to receive further instructions.
8.  Lateral Movement/Exfiltration: The attacker uses the compromised system as a pivot point to move laterally within the network or exfiltrate sensitive data.

## Impact

Successful exploitation leads to arbitrary code execution, potentially giving the attacker control over the compromised system. This can lead to data theft, system compromise, lateral movement within the network, and ultimately, significant business disruption. Depending on the level of access achieved, the attacker may be able to install ransomware, steal sensitive data, or disrupt critical business operations. The number of potential victims is broad, spanning across any organization where users have write access to the aforementioned suspicious directories.

## Recommendation

*   Enable file creation monitoring, specifically for the suspicious paths listed in the rules, using tools like Sysmon (logsource category: file_event, product: windows).
*   Deploy the Sigma rules provided to your SIEM to detect the creation of executable files in suspicious directories (rules).
*   Investigate any alerts generated by these rules to determine if the created files are malicious or benign.
*   Implement application control policies to restrict the execution of unauthorized executables in user directories (recommendation).
