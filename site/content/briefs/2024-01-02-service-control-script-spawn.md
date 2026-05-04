---
title: Service Control Executed from Script Interpreters
slug: 2024-01-02-service-control-script-spawn
description: Detection of Service Control (sc.exe) being spawned from script interpreter processes, such as PowerShell or cmd.exe, to create, modify, or start services, which may indicate privilege escalation or persistence attempts by an attacker.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - privilege-escalation
  - defense-evasion
  - execution
  - windows
  - service-creation
vendors:
  - Elastic
  - Microsoft
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - Windows Security Event Logs
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
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
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
references:
  - https://www.elastic.co/security-labs/invisible-miners-unveiling-ghostengine
rules:
  - title: Service Control Spawning via Script Interpreter
    description: Detects Service Control (sc.exe) spawning from script interpreter processes to create, modify, or start services.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - execution
      - privilege_escalation
    techniques:
      - T1059
      - T1543
    data_sources:
      - process_creation
      - windows
  - title: Service Control with Suspicious Arguments
    description: Detects suspicious arguments used with Service Control (sc.exe) that may indicate malicious activity.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - execution
      - privilege_escalation
    techniques:
      - T1543
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies instances where the Service Control utility (sc.exe) is executed from within a script interpreter, such as cmd.exe, PowerShell, or wscript.exe. Attackers may leverage this behavior to create, modify, or start Windows services, often with the intent to elevate privileges or establish persistence on a compromised system. The sc.exe is a legitimate Windows command-line tool used for managing services. Abusing this tool allows attackers to perform malicious actions under the guise of legitimate system administration. This detection is designed to identify anomalous use of sc.exe that deviates from typical administrative tasks, focusing on instances where it's spawned from scripting environments often used for malicious activities. The rule specifically excludes service creations performed by the SYSTEM user.

## Attack Chain

1. An attacker gains initial access to a Windows system via an exploit or compromised credentials.
2. The attacker executes a script interpreter (e.g., cmd.exe, powershell.exe).
3. Within the script interpreter, the attacker uses sc.exe to manage Windows services.
4. The sc.exe command is used with arguments such as "create", "start", "stop", "delete", or "config" to manipulate service configurations.
5. A new service is created or an existing service is modified to execute a malicious payload.
6. The malicious service is started, allowing the attacker to execute code with elevated privileges (SYSTEM).
7. The attacker achieves persistence by ensuring the malicious service automatically starts upon system reboot.
8. The attacker may use the created service to execute additional malicious commands or maintain remote access.

## Impact

A successful attack could lead to complete system compromise with the attacker gaining SYSTEM level privileges. This can allow for lateral movement within the network, data exfiltration, or installation of persistent backdoors. While the frequency of this specific technique may be low, the potential impact is high due to the elevated privileges gained.

## Recommendation

*   Deploy the Sigma rule `Service Control Spawning via Script Interpreter` to your SIEM to detect this specific behavior and tune it to your environment.
*   Monitor process creation events for sc.exe being executed by script interpreters like PowerShell or cmd.exe (as covered in the rule description).
*   Investigate any instances of sc.exe being used with the arguments "create", "start", "stop", "delete", or "config" from scripting environments to identify potentially malicious activity.
*   Ensure proper access controls are in place to limit the ability of users to create or modify services.
