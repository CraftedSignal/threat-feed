---
title: Exploitation of MSSQL xp_cmdshell for Persistence and Execution
slug: 2026-10-mssql-xp-cmdshell-persistence
description: Attackers can leverage the Microsoft SQL Server xp_cmdshell extended stored procedure to execute arbitrary OS commands, facilitating privilege escalation and persistence.
date: "2026-10-05T12:03:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - execution
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
    evidence: Attackers can use this to execute commands on the system running the SQL server, commonly to escalate their privileges and establish persistence.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: xp_cmdshell, which spawns a Windows command shell and passes in a string for execution.
    confidence_band: high
references:
  - https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/
rules:
  - title: Detect Execution via MSSQL xp_cmdshell
    description: Detects suspicious process creation stemming from the SQL Server process, which may indicate the use of xp_cmdshell for unauthorized code execution.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.003
      - T1505.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review all SQL server configurations to confirm xp_cmdshell is disabled.
      owner: IT Operations
      due: 24h
      evidence: The xp_cmdshell procedure is disabled by default, but when used, it has the same security context as the MSSQL Server service account.
  hunt_leads:
    - lead: Search for process execution logs where ParentImage is sqlservr.exe.
      technique_id: T1505.001
      data_needed:
        - Process creation events (Event ID 1)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Investigate the process execution chain (parent process tree) for unknown processes.
  mitigation_plan:
    - priority: immediate
      action: Disable xp_cmdshell stored procedure.
      owner: Database Administration
      addresses: T1505.001
      evidence: Disable the xp_cmdshell stored procedure.
---

Microsoft SQL Server (MSSQL) includes extended stored procedures designed to extend database functionality, such as interfacing with external programs. One such procedure, xp_cmdshell, spawns a Windows command shell to execute strings passed as arguments. Because this procedure runs with the same security context as the MSSQL Server service account, it often executes with high privileges. While xp_cmdshell is disabled by default in standard configurations, attackers who successfully compromise a SQL server frequently enable this feature to execute arbitrary system commands, establish persistence, or conduct further post-exploitation activities. This technique is a common vector for adversaries looking to transition from database-level access to full operating system control. Defenders should scrutinize any process spawning from sqlservr.exe, especially when involving command-line interpreters or administrative tools.

## Attack Chain

1. Initial access is gained to the SQL server instance (e.g., via brute force or web application vulnerability).
2. The attacker uses SQL queries to alter the server configuration (e.g., 'sp_configure') to enable the 'show advanced options' setting.
3. The attacker enables the 'xp_cmdshell' feature within the SQL Server configuration.
4. The attacker invokes 'xp_cmdshell' via a T-SQL command to execute a malicious payload.
5. The 'sqlservr.exe' process spawns a child process, such as 'cmd.exe', 'powershell.exe', or other binaries.
6. The spawned process executes arbitrary commands, such as downloading additional malware, modifying system files, or creating local administrative users.
7. The attacker leverages these commands to establish long-term persistence on the host.

## Impact

Successful exploitation allows an attacker to execute arbitrary code with the privileges of the MSSQL service account. This can result in full system compromise, exfiltration of sensitive database content, deployment of ransomware, or the establishment of persistent backdoors on the affected Windows server.

## Recommendation

Prioritize the following actions to detect and mitigate unauthorized use of xp_cmdshell:

- Disable the xp_cmdshell stored procedure on all SQL servers unless there is a documented business requirement.
- Implement strict allowlists for processes spawned by 'sqlservr.exe' using the provided detection rules.
- Audit configuration changes for SQL servers to identify unauthorized attempts to toggle 'xp_cmdshell'.
- Restrict SQL Server service account permissions to the minimum necessary for database operations to limit the impact of code execution.
- Ensure SQL servers are not directly reachable from the internet to prevent unauthenticated access.
- Deploy the Sigma rules below to monitor for suspicious process creation originating from the SQL server process tree.
