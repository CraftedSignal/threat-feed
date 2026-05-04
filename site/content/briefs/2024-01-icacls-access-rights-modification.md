---
title: Windows Files and Dirs Access Rights Modification via Icacls
slug: 2024-01-icacls-access-rights-modification
description: Detection of icacls.exe, cacls.exe, or xcacls.exe being used to modify file or directory permissions, often used by APTs and coinminers for defense evasion and persistence.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - persistence
  - windows
  - access-control
vendors:
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1222
    technique_name: File and Directory Permissions Modification
references:
  - https://malpedia.caad.fkie.fraunhofer.de/details/win.amadey
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_files_and_dirs_access_rights_modification_via_icacls.yml
rules:
  - title: Detect Suspicious Icacls Usage
    description: Detects suspicious usage of icacls.exe, cacls.exe, or xcacls.exe to modify file or directory permissions.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1222.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Icacls Modification of Specific Files
    description: Detects icacls.exe being used to modify permissions on specific files or directories known to be targeted by attackers.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1222.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This analytic detects the modification of file and directory security permissions through command-line tools like icacls.exe, cacls.exe, and xcacls.exe. These tools are legitimate Windows utilities but are often abused by threat actors, including APT groups and coinminer scripts, to evade detection, maintain persistence, and hinder incident response. The detection focuses on command-line arguments indicating modifications to access rights (e.g., granting full control or modifying permissions). Detecting this activity is crucial as it can lead to unauthorized access, data exfiltration, and system compromise, ultimately impeding remediation efforts and prolonging the attacker's presence on the compromised system. The detection leverages endpoint detection and response (EDR) data focusing on process execution and command-line analysis.

## Attack Chain

1.  Initial Access: The attacker gains initial access to the system through methods such as phishing, exploiting vulnerabilities, or compromised credentials.
2.  Privilege Escalation: The attacker escalates privileges to obtain necessary permissions for modifying file and directory access rights. This can be achieved through exploiting system vulnerabilities or using stolen credentials with elevated privileges.
3.  Tool Deployment: The attacker deploys or utilizes existing system tools like `icacls.exe`, `cacls.exe`, or `xcacls.exe` to modify access control lists (ACLs) on files and directories.
4.  Access Rights Modification: The attacker uses the deployed tools to modify the ACLs of critical system files or directories, potentially granting themselves full control or restricting access for legitimate users and security software. Specific command-line arguments like `*:R*`, `*:W*`, `*:F*`, `*:C*`, `*:N*`, `*/P*`, and `*/E*` are used to manipulate access rights.
5.  Defense Evasion: By modifying access rights, the attacker attempts to evade detection by security software and hinders incident response efforts by restricting access to forensic data or security tools.
6.  Persistence: The attacker establishes persistence by modifying the access rights of startup scripts or registry keys, ensuring that their malicious code executes even after system reboots.
7.  Lateral Movement: The attacker uses the modified access rights to access files and directories on other systems within the network, facilitating lateral movement and further compromise.
8.  Impact: The attacker achieves their final objective, such as data exfiltration, system disruption, or deploying ransomware, by leveraging the modified access rights to access and manipulate sensitive data or critical system resources.

## Impact

Successful exploitation allows attackers to persist on the system, evade detection, and potentially move laterally within the network. Modification of file and directory permissions can hinder investigation, impede remediation efforts, and maintain persistent access to the compromised environment. The impact ranges from data theft to complete system compromise and denial of service. This activity is often associated with APT groups and coinminer operations.

## Recommendation

*   Enable Sysmon process creation logging (Event ID 1) to capture the execution of `icacls.exe`, `cacls.exe`, and `xcacls.exe`.
*   Deploy the Sigma rule "Detect Suspicious Icacls Usage" to your SIEM to identify instances of access right modifications via icacls.exe, cacls.exe, and xcacls.exe.
*   Investigate any instances where these tools are used to modify access rights, especially when command-line arguments include `*:R*`, `*:W*`, `*:F*`, `*:C*`, `*:N*`, `*/P*`, and `*/E*`.
*   Monitor Windows Event Log Security (4688) for process creation events to correlate with Sysmon data.
