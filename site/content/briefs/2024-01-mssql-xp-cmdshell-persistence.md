---
title: MSSQL xp_cmdshell Stored Procedure Abuse for Persistence
slug: 2024-01-mssql-xp-cmdshell-persistence
description: Attackers may leverage the xp_cmdshell stored procedure in Microsoft SQL Server to execute arbitrary commands for privilege escalation and persistence, often bypassing default security configurations.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - persistence
  - sql-server
  - xp_cmdshell
  - windows
vendors:
  - Microsoft
products:
  - SQL Server
affected_os:
  - Windows
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
rules:
  - title: Detect Suspicious xp_cmdshell Usage
    description: Detects the execution of commands via the xp_cmdshell extended stored procedure in SQL Server, which can indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1505.001
    data_sources:
      - process_creation
      - windows
  - title: Detect xp_cmdshell Enabling via Stored Procedure
    description: Detects attempts to enable the xp_cmdshell stored procedure in SQL Server, a prerequisite for its abuse.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1505.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The xp_cmdshell extended stored procedure in Microsoft SQL Server allows execution of operating system commands from within the SQL Server environment. Although disabled by default, its use can provide a direct pathway for attackers to run arbitrary commands on the underlying system with the privileges of the SQL Server service account. This account often has elevated privileges, allowing attackers to escalate their access and establish persistence mechanisms. This activity has been observed in intrusions where attackers seek to maintain control over compromised systems. Defenders should closely monitor for the enabling and use of xp_cmdshell, especially when combined with other suspicious activity.

## Attack Chain

1. An attacker gains initial access to a vulnerable SQL Server instance, possibly through SQL injection or compromised credentials.
2. The attacker attempts to enable the xp_cmdshell stored procedure using `sp_configure 'xp_cmdshell', 1; RECONFIGURE;`.
3. The attacker uses xp_cmdshell to execute reconnaissance commands, such as `xp_cmdshell 'whoami'` or `xp_cmdshell 'net user'` to gather information about the system and user context.
4. The attacker uses xp_cmdshell to download and execute a malicious payload (e.g., using `certutil.exe` to download a file).
5. The attacker establishes persistence by creating a scheduled task via xp_cmdshell executing the `schtasks` command. For example: `xp_cmdshell 'schtasks /create /tn "Malicious Task" /tr "C:\\Windows\\Temp\\evil.exe" /sc ONLOGON /ru SYSTEM'`.
6. The scheduled task executes upon system logon, providing persistent access for the attacker.
7. The attacker uses the persistent access to deploy additional tools or exfiltrate data.

## Impact

Successful exploitation enables attackers to execute arbitrary commands with elevated privileges on the SQL Server host. This can lead to data theft, system compromise, and the establishment of persistent backdoors. Lateral movement within the network is also possible, leveraging the compromised SQL Server as a pivot point. While specific victim counts and sectors are not provided, any organization using MSSQL Server is potentially vulnerable.

## Recommendation

*   Deploy the Sigma rule "Detect Suspicious xp_cmdshell Usage" to your SIEM to detect attempts to use xp_cmdshell for command execution.
*   Disable the xp_cmdshell stored procedure unless absolutely necessary. If required, implement strict monitoring and auditing of its usage (reference: rule description).
*   Monitor for process creation events with a parent process of `sqlservr.exe`, specifically looking for command-line arguments indicative of exploitation (reference: Sigma rule).
*   Ensure SQL servers are not directly exposed to the internet and implement strict access controls, using allowlists to restrict connections to legitimate sources (reference: the "Response and remediation" section).
