---
title: IIS HTTP Logging Disabled
slug: 2024-01-iis-http-logging-disabled
description: An attacker with IIS server access can disable HTTP Logging using appcmd.exe with the /dontLog parameter as an anti-forensics measure.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - windows
  - iis
vendors:
  - Microsoft
products:
  - IIS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://attack.mitre.org/techniques/T1562/
  - https://attack.mitre.org/techniques/T1562/002/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: IIS HTTP Logging Disabled
    description: Detects when IIS HTTP Logging is disabled via appcmd.exe
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
  - title: IIS Appcmd.exe Execution from Unusual Location
    description: Detects appcmd.exe executed from unusual parent processes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers with access to an IIS server, potentially through a webshell or other means, may attempt to disable HTTP logging to evade detection and hinder forensic investigations. This activity involves using the `appcmd.exe` utility, a command-line tool for managing IIS, to modify the server's logging configuration. Specifically, the attacker uses the `/dontLog*:*True` parameter with `appcmd.exe` to disable HTTP logging. This action prevents the server from recording web requests, making it more difficult to detect malicious activity, such as webshell execution, unauthorized access, or data exfiltration. The targeted systems are Windows servers running IIS. Disabling logging helps attackers cover their tracks and prolong their presence on the compromised system.

## Attack Chain

1. The attacker gains initial access to the Windows server, possibly through exploiting a vulnerability or using stolen credentials.
2. The attacker uploads or otherwise deploys a webshell to a publicly accessible directory within the IIS webroot.
3. The attacker authenticates to the webshell via HTTP requests.
4. The attacker executes commands through the webshell, gaining command-line access to the server.
5. The attacker uses `appcmd.exe` to disable IIS HTTP logging by using the `/dontLog*:*True` parameter.
6. The command is executed to modify the IIS configuration, preventing further HTTP request logging.
7. The attacker performs malicious activities, such as lateral movement, data theft, or further exploitation, without generating HTTP logs.
8. The attacker maintains persistence on the system, potentially through other backdoors or scheduled tasks.

## Impact

Successful disabling of IIS HTTP logging results in a loss of valuable forensic data, hindering incident response and threat hunting efforts. This can lead to a prolonged attacker presence, increased data exfiltration, and further system compromise. Without HTTP logs, detecting webshell activity, identifying exploited vulnerabilities, and tracing attacker actions becomes significantly more difficult.

## Recommendation

*   Enable Sysmon process creation logging to detect the execution of `appcmd.exe` with suspicious parameters (Data Source: Sysmon, Windows Security Event Logs).
*   Deploy the Sigma rule "IIS HTTP Logging Disabled" to your SIEM and tune for your environment to detect disabling of IIS HTTP Logging.
*   Monitor parent processes of `appcmd.exe` to identify potential webshell activity or unauthorized command execution (Data Source: Elastic Endgame, Elastic Defend).
*   Review and enforce strict access controls for IIS servers to prevent unauthorized modifications to the server configuration (OS: Windows).
