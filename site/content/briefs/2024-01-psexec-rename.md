---
title: Suspicious Process Execution via Renamed PsExec Executable
slug: 2024-01-psexec-rename
description: The rule identifies suspicious PsExec activity where the psexec service is executed from a renamed executable, possibly to evade detection and enable lateral movement.
date: "2024-01-09T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - psexec
  - lateral-movement
  - defense-evasion
  - windows
vendors:
  - Microsoft
products:
  - PsExec
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://attack.mitre.org/techniques/T1569/
  - https://attack.mitre.org/techniques/T1569/002/
  - https://attack.mitre.org/techniques/T1036/
  - https://attack.mitre.org/techniques/T1036/003/
  - https://attack.mitre.org/techniques/T1021/
  - https://attack.mitre.org/techniques/T1021/002/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/execution_suspicious_psexesvc.toml
rules:
  - title: Suspicious Process Execution via Renamed PsExec Executable
    description: Detects execution of psexesvc.exe with a different process name, indicating possible evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - lateral_movement
    techniques:
      - T1021.002
      - T1036.003
      - T1569.002
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Original File Name for PsExec
    description: Detects process execution where the original file name is PSEXESVC.exe but the process name is not.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - execution
      - lateral_movement
    techniques:
      - T1021.002
      - T1036.003
      - T1569.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This rule detects the execution of PsExec service components with non-standard names, potentially indicating an attempt to evade detection. PsExec, a legitimate tool from Sysinternals, is frequently abused by attackers for lateral movement and remote command execution with SYSTEM privileges. Attackers often rename binaries to bypass security measures that rely on default file names. The targeted systems are Windows-based. This activity is important because successful exploitation can lead to privilege escalation, lateral movement, and ultimately, compromise of the target environment. The rule specifically looks for processes where the original filename is psexesvc.exe but the actual process name is not PSEXESVC.exe.

## Attack Chain

1.  The attacker gains initial access to a system, possibly through phishing or exploiting a vulnerability.
2.  The attacker uploads a renamed version of PsExec (e.g., renamed_psexec.exe) onto the compromised system.
3.  The attacker uses the renamed PsExec executable to initiate a connection to a remote target system, specifying commands to execute.
4.  The renamed PsExec executable copies its service component (psexesvc.exe) to the ADMIN$ share on the target system, but with a modified name (e.g., abc.exe).
5.  The renamed service component (abc.exe) is executed on the target system, running the attacker-specified commands with SYSTEM privileges.
6.  The attacker performs actions like credential dumping, reconnaissance, or malware deployment on the target system.
7.  The attacker leverages the compromised system to move laterally to other systems within the network.
8.  The attacker achieves their final objective, which may include data exfiltration, ransomware deployment, or disruption of services.

## Impact

Successful execution of renamed PsExec can lead to unauthorized remote command execution with SYSTEM privileges. This allows attackers to perform lateral movement, escalate privileges, and compromise sensitive data. The impact includes potential data breaches, system downtime, and reputational damage. While the exact number of victims is unknown, this technique is broadly applicable across Windows environments, affecting any organization that does not adequately monitor and restrict PsExec usage.

## Recommendation

*   Deploy the Sigma rule "Suspicious Process Execution via Renamed PsExec Executable" to your SIEM and tune for your environment to detect this specific behavior.
*   Enable Sysmon process creation logging to capture the necessary process metadata (Image, OriginalFileName, CommandLine) required for the provided Sigma rule.
*   Implement application control policies to restrict the execution of unauthorized executables, including renamed versions of PsExec.
*   Monitor network connections for SMB traffic originating from unusual processes, which might indicate PsExec activity.
*   Review and enforce the principle of least privilege to limit the potential impact of compromised accounts.
