---
title: Potential Veeam Credential Access via SQL Commands
slug: 2024-07-veeam-credential-access
description: Attackers can leverage sqlcmd.exe or PowerShell commands like Invoke-Sqlcmd to access Veeam credentials stored in MSSQL databases, potentially targeting backups for destructive operations such as ransomware attacks.
date: "2024-07-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - veeam
  - credential-access
  - mssql
  - windows
  - ransomware
vendors:
  - Microsoft
  - Veeam
products:
  - Microsoft Defender XDR
  - Veeam Backup
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
references:
  - https://thedfirreport.com/2021/12/13/diavol-ransomware/
rules:
  - title: Potential Veeam Credential Access Command via sqlcmd
    description: Detects the execution of sqlcmd.exe with arguments that attempt to access Veeam credentials in MSSQL databases.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
  - title: Potential Veeam Credential Access Command via PowerShell
    description: Detects the use of PowerShell commands like Invoke-Sqlcmd to access Veeam credentials in MSSQL databases.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers are increasingly targeting backup infrastructure to maximize the impact of ransomware and data exfiltration attacks. Veeam, a popular backup and disaster recovery solution, stores credentials for backup operations in MSSQL databases. An attacker who gains access to these databases may attempt to use tools like `sqlcmd.exe` or PowerShell commands (e.g., `Invoke-Sqlcmd`) to extract and decrypt these credentials. This tactic allows the attacker to compromise the backups themselves, preventing recovery and increasing pressure on the victim. This activity has been observed in real-world incidents, such as those involving the Diavol ransomware. Defenders should monitor for suspicious command-line activity targeting Veeam credentials within MSSQL environments.

## Attack Chain

1. Initial access to the target environment is gained through methods such as phishing or exploiting a vulnerability in a public-facing application.
2. The attacker performs reconnaissance to identify the location of the Veeam MSSQL database server.
3. The attacker obtains valid credentials or exploits a vulnerability to gain access to the Veeam MSSQL database server.
4. The attacker executes `sqlcmd.exe` or uses PowerShell commands (e.g., `Invoke-Sqlcmd`) to query the `[VeeamBackup].[dbo].[Credentials]` table.
5. The attacker retrieves the encrypted Veeam credentials from the database.
6. The attacker decrypts the Veeam credentials using custom scripts or tools, potentially leveraging the Veeam backup server itself.
7. The attacker uses the compromised Veeam credentials to access and delete or encrypt backup data.
8. The attacker deploys ransomware on the remaining systems, knowing that recovery from backups is now impossible.

## Impact

Successful compromise of Veeam credentials can have devastating consequences. Attackers can encrypt or delete backup data, making recovery impossible and significantly increasing the impact of ransomware attacks. This can lead to prolonged downtime, data loss, financial losses, and reputational damage. Organizations relying on Veeam for backup and recovery should prioritize monitoring and securing their Veeam infrastructure to prevent credential access and backup compromise.

## Recommendation

*   Enable Sysmon process creation logging to capture command-line activity, specifically `sqlcmd.exe` and PowerShell.
*   Deploy the Sigma rule "Potential Veeam Credential Access Command" to detect suspicious command executions targeting Veeam credentials in MSSQL databases.
*   Review and restrict access controls to the Veeam MSSQL database, ensuring only authorized personnel and services have access.
*   Monitor for unusual login activity and failed login attempts to the Veeam MSSQL database server.
*   Implement multi-factor authentication for all accounts with access to Veeam infrastructure.
*   Regularly audit Veeam backup configurations and logs to identify any unauthorized modifications or access attempts.
