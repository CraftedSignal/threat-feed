---
title: System Shells Launched via Windows Services
slug: 2024-01-system-shells-via-services
description: Attackers may configure existing Windows services or create new ones to execute system shells (cmd.exe, powershell.exe) to elevate privileges from administrator to SYSTEM for persistence and further malicious activity.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - execution
  - windows
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Windows
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
    description: Detects command interpreters spawned by services.exe, indicating potential privilege escalation or persistence.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.001
      - T1059.003
      - T1543.003
      - T1569.002
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Service Creation with Command Interpreter
    description: Detects the creation of a service where the service binary is a command interpreter (cmd.exe, powershell.exe, etc.)
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers can abuse Windows services, which typically run as SYSTEM, to escalate privileges. This involves configuring existing services or creating new ones to execute system shells, such as `cmd.exe` or `powershell.exe`, to gain SYSTEM permissions. This technique can also establish persistence by ensuring the malicious shell is executed every time the service starts. The rule "System Shells via Services" aims to detect such activity by identifying instances where `services.exe` spawns command interpreters, indicating a potential privilege escalation or persistence attempt. This detection focuses on the relationship between `services.exe` and the spawned shell processes.

## Attack Chain

1. An attacker gains initial access to the system with administrative privileges.
2. The attacker identifies a vulnerable or misconfigured service, or creates a new service using tools like `sc.exe` or PowerShell.
3. The service configuration is modified to execute a command interpreter (cmd.exe, powershell.exe, pwsh.exe, powershell_ise.exe) instead of its legitimate function. This modification can be achieved through registry edits or command-line tools.
4. The service is started or restarted, either manually or automatically during system boot.
5. `services.exe` spawns the configured command interpreter.
6. The command interpreter executes attacker-controlled commands with SYSTEM privileges. This might include downloading and executing malware, modifying system settings, or exfiltrating data.
7. The attacker leverages the SYSTEM privileges to move laterally within the network.

## Impact

Successful exploitation allows attackers to gain SYSTEM-level access on the compromised host. This level of access allows for complete control over the system, including installing malicious software, modifying system configurations, stealing sensitive data, and potentially pivoting to other systems on the network. The impact can range from data breaches and system outages to complete compromise of the affected network.

## Recommendation

*   Deploy the Sigma rule "System Shells via Services" to your SIEM to detect this activity.
*   Enable Sysmon process creation logging to ensure the rule can capture the necessary events.
*   Investigate any instances of `services.exe` spawning command interpreters to determine if the activity is legitimate or malicious.
