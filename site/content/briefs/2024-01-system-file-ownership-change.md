---
title: System File Ownership Change for Defense Evasion
slug: 2024-01-system-file-ownership-change
description: Adversaries may modify file or directory ownership to evade access control lists (ACLs) and access protected files, often using icacls.exe or takeown.exe to reset permissions on system files.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - persistence
  - windows
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
  - Crowdstrike
products:
  - Microsoft Defender XDR
  - Elastic Defend
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1222
    technique_name: File and Directory Permissions Modification
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_modify_ownership_os_files.toml
  - https://attack.mitre.org/techniques/T1222/
  - https://attack.mitre.org/techniques/T1222/001/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: Suspicious Takeown Execution
    description: Detects the execution of takeown.exe with arguments targeting files, which may indicate an attempt to take ownership of files for malicious purposes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1222
      - T1222.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Icacls Reset Permissions
    description: Detects the use of icacls.exe to reset permissions on files, potentially indicating an attempt to evade access controls.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1222
      - T1222.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Icacls Grant Everyone Full Control
    description: Detects the use of icacls.exe to grant full control to everyone on files, which weakens security.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1222
      - T1222.001
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Attackers often attempt to modify file or directory ownership to bypass access controls and gain unauthorized access to sensitive data or system resources. This involves altering permissions associated with critical files or directories, granting broader access to accounts under attacker control or resetting permissions to default values which might be more permissive. This defense evasion technique can be used to establish persistence, escalate privileges, or exfiltrate data without triggering standard security alerts. The common tools used include `icacls.exe` and `takeown.exe`, typically targeting files within the `C:\Windows\` directory.

## Attack Chain

1.  Initial access is achieved through an existing compromised account or vulnerability.
2.  The attacker uses `takeown.exe /f <file>` to take ownership of a target file or directory.
3.  The attacker uses `icacls.exe <file> /reset` to reset the ACL of the file or directory.
4.  Alternatively, the attacker uses `icacls.exe <file> /grant Everyone:F` to grant full control to everyone, weakening security.
5.  The attacker modifies the contents of the file, such as injecting malicious code or configuration changes.
6.  The attacker leverages the modified file for persistence, such as a modified system DLL loaded at boot.
7.  The system executes the malicious code when the compromised file is accessed or executed.
8.  The attacker achieves their objective, such as maintaining persistence, escalating privileges, or executing arbitrary commands.

## Impact

Compromising file and directory permissions can lead to significant security breaches. Successful attacks can allow unauthorized access to sensitive data, system instability, or the execution of malicious code with elevated privileges. This can affect any Windows environment where file permissions are improperly managed, with potential for widespread system compromise and data exfiltration. The impact is most severe on systems containing sensitive data or critical infrastructure components.

## Recommendation

*   Monitor process execution for `icacls.exe` and `takeown.exe` with suspicious arguments targeting system files (e.g., `C:\Windows\*`) to detect potential permission modification attempts using the provided Sigma rules.
*   Enable Windows Security Auditing for file system changes to capture events related to permission modifications and ownership changes.
*   Deploy the provided Sigma rules to your SIEM and tune for your environment, specifically focusing on processes modifying permissions on files within the `C:\Windows\` directory.
*   Investigate any alerts triggered by the Sigma rules, focusing on the process execution chain and the target files being modified.
