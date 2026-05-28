---
title: Windows SQL Server xp_cmdshell Configuration Change Detected
slug: 2026-05-windows-sql-server-xp-cmdshell-config-change
description: Detection of changes to the xp_cmdshell configuration in SQL Server, a feature often abused by attackers for privilege escalation and lateral movement by enabling execution of operating system commands.
date: "2026-05-28T18:01:59Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql_server
  - xp_cmdshell
  - privilege_escalation
  - lateral_movement
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - SQL Server
  - Splunk Enterprise Security
  - Splunk Enterprise
  - Splunk Cloud
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1505
    technique_name: Server Software Component
references:
  - https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql
  - https://attack.mitre.org/techniques/T1505/003/
  - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/xp-cmdshell-server-configuration-option
rules:
  - title: Windows SQL Server xp_cmdshell Enabled
    description: Detects when xp_cmdshell is enabled in SQL Server by monitoring Windows Application Event Log ID 15457.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1505.001
    data_sources:
      - application
      - windows
  - title: Windows SQL Server xp_cmdshell Disabled
    description: Detects when xp_cmdshell is disabled in SQL Server by monitoring Windows Application Event Log ID 15457.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1505.001
    data_sources:
      - application
      - windows
rules_count: 2
---

The xp_cmdshell extended stored procedure in Microsoft SQL Server allows execution of operating system commands and programs from within the SQL Server environment. While legitimate uses exist, this feature is often abused by attackers to gain unauthorized access, escalate privileges, and move laterally within a network. This detection focuses on identifying modifications to the xp_cmdshell configuration within SQL Server instances. Specifically, it detects changes indicated by Windows Event ID 15457, which signals that the configuration of an extended stored procedure has been altered. It is crucial to monitor changes to this setting since threat actors often enable xp_cmdshell to execute malicious commands, install backdoors, or exfiltrate sensitive data.

## Attack Chain

1.  Attacker gains initial access to a SQL Server instance through compromised credentials or by exploiting a vulnerability (e.g., SQL injection).
2.  The attacker attempts to enable the xp_cmdshell extended stored procedure if it is currently disabled.
3.  The attacker executes the `sp_configure` stored procedure to modify the `xp_cmdshell` configuration option.
4.  The attacker sets the configuration option to '1' to enable xp_cmdshell.
5.  The SQL Server instance logs an event with Event ID 15457, indicating a change to the `xp_cmdshell` configuration.
6.  The attacker leverages `xp_cmdshell` to execute operating system commands, such as creating new user accounts, installing malware, or accessing sensitive files.
7.  The attacker moves laterally to other systems within the network by exploiting trusted relationships or by using the compromised SQL Server instance as a pivot point.
8.  The attacker exfiltrates data or achieves other malicious objectives.

## Impact

Successful modification and abuse of `xp_cmdshell` can lead to complete compromise of the SQL Server instance and potentially the entire network. Attackers can execute arbitrary commands, install persistent backdoors, steal sensitive data, and disrupt critical business operations. Given its power and potential for abuse, any unauthorized modification to the `xp_cmdshell` configuration must be treated as a critical security incident.

## Recommendation

*   Enable Windows Event Logging on SQL Server instances and ingest the logs into a SIEM to detect Event ID 15457 ([Windows Event Log Application 15457](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql)).
*   Deploy the provided Sigma rule (`Windows SQL Server xp_cmdshell Enabled`) to detect when xp_cmdshell is enabled via Event ID 15457.
*   Deploy the provided Sigma rule (`Windows SQL Server xp_cmdshell Disabled`) to detect when xp_cmdshell is disabled via Event ID 15457.
*   Review the official Microsoft documentation and references to understand the risks associated with xp_cmdshell and the best practices for securing SQL Server instances ([references](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql)).
*   Implement strict access control policies to limit who can modify SQL Server configurations.
