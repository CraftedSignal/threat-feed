---
title: Privilege Escalation via Windows Token Theft
slug: 2024-01-09-token-theft-privilege-escalation
description: An adversary may create a new process with a different token to escalate privileges and bypass access controls by creating a process running as SYSTEM and impersonating a Windows core binary.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - token-theft
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1134
    technique_name: Access Token Manipulation
references:
  - https://lengjibo.github.io/token/
  - https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw
  - https://attack.mitre.org/techniques/T1134/
  - https://attack.mitre.org/techniques/T1134/002/
  - https://attack.mitre.org/tactics/TA0004/
rules:
  - title: Process Created with SYSTEM Token Impersonating Windows Binary
    description: Detects process creation events where a process runs as SYSTEM and its effective parent is a Windows core binary, indicating potential token theft.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1134.002
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Created with SYSTEM Token and Non-Standard Path
    description: Detects process creation events where a process runs as SYSTEM but the executable is located in a suspicious path.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1134.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies potential privilege escalation attempts on Windows systems via token theft. The technique involves an attacker creating a new process with an elevated token, effectively impersonating a highly privileged account such as SYSTEM (NT AUTHORITY\SYSTEM). This allows the attacker to bypass access controls and perform actions normally restricted to privileged users or services. The detection focuses on identifying processes running as SYSTEM whose parent process is a Windows core binary, a common target for token theft. The rule is designed to ignore common false positives such as the Windows Utility Manager, print spooler service, error reporting executables, and Windows updates to minimize alert fatigue. This technique is observed across various threat actors seeking to gain higher-level access within a compromised system.

## Attack Chain

1.  The attacker gains initial access to the system through an exploit or compromised credentials.
2.  The attacker identifies a privileged process running as SYSTEM, often a core Windows service.
3.  The attacker injects malicious code into a running process or executes code from a location on disk.
4.  The injected code duplicates the SYSTEM token from the target process using Windows API calls such as `OpenProcessToken` and `DuplicateTokenEx`.
5.  The attacker creates a new process using `CreateProcessWithTokenW`, specifying the duplicated SYSTEM token, thus creating a new process running with SYSTEM privileges.
6.  The newly created process performs malicious actions, such as installing backdoors, modifying system configurations, or accessing sensitive data.
7.  The attacker leverages the elevated privileges to move laterally within the network and compromise additional systems.
8.  The final objective is often data exfiltration, ransomware deployment, or establishing persistent control over the compromised environment.

## Impact

Successful exploitation allows the attacker to perform any action on the system, including installing programs, viewing, changing, or deleting data, and creating new accounts with full administrative rights. This can lead to complete system compromise, data breaches, and significant disruption of services. In a domain environment, privilege escalation on a single system can lead to domain-wide compromise, affecting all connected machines and resources.

## Recommendation

*   Deploy the "Process Created with an Elevated Token" rule to your SIEM and tune the filters based on your environment to minimize false positives.
*   Enable process creation logging with command-line arguments in your endpoint security solution to provide the necessary data for the provided Sigma rules.
*   Regularly review and update the exclusion lists in the Sigma rules to account for legitimate software in your environment that may trigger false positives.
*   Implement strong access control policies and regularly audit user privileges to minimize the impact of successful token theft.
*   Monitor for the use of `CreateProcessWithTokenW` API calls within your environment to detect potential token manipulation attempts.
