---
title: System Shells Launched via Windows Services
slug: 2024-01-system-shells-via-services
description: Attackers may configure existing services or create new ones to execute system shells to elevate their privileges from administrator to SYSTEM, using services.exe as the parent process of the shell.
date: "2024-01-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - execution
  - privilege_escalation
  - windows
vendors:
  - Microsoft
  - Elastic
products:
  - Windows
  - Elastic Defend
  - Microsoft Defender XDR
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
references:
  - https://attack.mitre.org/techniques/T1543/
  - https://attack.mitre.org/techniques/T1543/003/
  - https://attack.mitre.org/techniques/T1059/
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1059/003/
  - https://attack.mitre.org/techniques/T1569/
  - https://attack.mitre.org/techniques/T1569/002/
rules:
  - title: System Shells via Services
    description: Detects system shells spawned by services.exe, indicating potential privilege escalation and persistence.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.001
      - T1543.003
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Service Creation with Shell
    description: Detects the creation of a new service that executes a command shell.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.003
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

Attackers may configure existing Windows services or create new ones to execute system shells, in order to elevate their privileges from administrator to SYSTEM. This tactic is used to gain SYSTEM permissions and establish persistence. The detection rule focuses on identifying instances where `services.exe` is the parent process of a command shell (cmd.exe, powershell.exe, pwsh.exe, powershell_ise.exe), indicating that a service is being abused to run a shell. The rule is designed to work with data from Elastic Defend, CrowdStrike, Microsoft Defender XDR, SentinelOne Cloud Funnel, Sysmon, and Windows Security Event Logs.

## Attack Chain

1.  Attacker gains initial access to the system with administrator privileges.
2.  Attacker identifies a legitimate service or creates a new service to abuse for privilege escalation.
3.  Attacker modifies the service configuration to execute a command shell (cmd.exe, powershell.exe, pwsh.exe, or powershell_ise.exe). This may involve modifying the service's executable path or adding command-line arguments.
4.  The system's Service Control Manager (SCM) starts the service.
5.  `services.exe` spawns the configured command shell process.
6.  The command shell executes with SYSTEM privileges.
7.  Attacker uses the SYSTEM shell to perform malicious activities, such as installing malware, accessing sensitive data, or creating new user accounts.
8.  The service continues to run, providing persistent access to the system.

## Impact

Successful exploitation leads to privilege escalation to SYSTEM, granting the attacker complete control over the compromised system. This can result in data theft, malware installation, or further lateral movement within the network. The rule has a risk score of 47 and is categorized as medium severity.

## Recommendation

*   Deploy the Sigma rule `System Shells via Services` to detect the execution of command shells spawned by `services.exe` within your SIEM environment, and tune for your environment.
*   Investigate any process creation events where `services.exe` is the parent process of `cmd.exe`, `powershell.exe`, `pwsh.exe`, or `powershell_ise.exe` using the investigation guide provided in the content section.
*   Review service creation and modification events in Windows Event Logs (Event IDs 4697 and 7045) for suspicious entries.
*   Enable Sysmon process creation logging (Event ID 1) to capture detailed process information.
*   Utilize osquery to retrieve detailed service information to identify potentially malicious services. Reference queries $osquery_0, $osquery_1, and $osquery_2 in the investigation guide.
