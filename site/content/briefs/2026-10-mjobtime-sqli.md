---
title: Unauthenticated SQL Injection and RCE in mJobTime
slug: 2026-10-mjobtime-sqli
description: mJobTime builds through 15.7.3.32 contain an unauthenticated SQL injection vulnerability in Login.aspx allowing attackers to execute arbitrary commands as LocalSystem via xp_cmdshell.
date: "2026-10-08T17:11:02Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:mjobtime:mjobtime:*:*:*:*:*:*:*:*
tags:
  - injection
  - rce
  - authentication-bypass
vendors:
  - mJobTime
products:
  - mJobTime (<= 15.7.3.32)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: mJobTime through build 15.7.3.32 contains an unauthenticated SQL execution vulnerability
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can submit arbitrary SQL... to invoke xp_cmdshell... achieving pre-authentication remote code execution
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1505.001
    technique_name: 'Server Software Component: SQL Stored Procedures'
    evidence: queries are executed... using DBA/sysadmin privileges... invoke xp_cmdshell
    confidence_band: high
cves:
  - id: CVE-2026-9209
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9209
rules:
  - title: Detects CVE-2026-9209 Exploitation - SQL Injection Attempt in mJobTime
    description: Detects unauthenticated POST requests to Login.aspx attempting to invoke xp_cmdshell via the vulnerable runQueryButton or exportSqlQuery_Server methods.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Block external access to /Login.aspx on mJobTime servers
      owner: SOC
      due: 24h
      evidence: Unauthenticated RCE vulnerability reported in Login.aspx
  mitigation_plan:
    - priority: immediate
      action: Upgrade mJobTime to version 15.7.3.33 or later
      owner: IT Operations
      addresses: CVE-2026-9209
      evidence: Vulnerability affects builds up to 15.7.3.32
---

mJobTime builds through 15.7.3.32 are vulnerable to a critical unauthenticated SQL injection vulnerability located within the Login.aspx administrative panel. The vulnerability stems from improper input validation in the 'runQueryButton' postback and 'exportSqlQuery_Server' PageMethod, which allow unauthenticated users to execute arbitrary SQL commands against the backend Sybase SQL Anywhere database. Crucially, these queries are executed with DBA or sysadmin-level database privileges. 

The application relies on client-side 'sessionStorage' flags for authentication, which can be easily bypassed by an attacker submitting a specifically crafted HTTP request. By leveraging the database's administrative privileges, an attacker can invoke powerful stored procedures such as 'xp_cmdshell' to execute arbitrary operating system commands. This flaw permits complete system compromise, enabling the attacker to run code with the privileges of the database service, typically LocalSystem, with a single unauthenticated HTTP request. Organizations using mJobTime are at high risk of total system takeover and data exfiltration.

## Attack Chain

1. Attacker identifies a target instance of mJobTime running a vulnerable build (<= 15.7.3.32).
2. Attacker crafts a malicious HTTP POST request targeting the /Login.aspx page.
3. Attacker targets the 'runQueryButton' postback or 'exportSqlQuery_Server' PageMethod.
4. Attacker inserts a payload designed to bypass client-side authentication checks.
5. Attacker injects a malicious SQL query containing the 'xp_cmdshell' stored procedure.
6. The database executes the injected SQL command with DBA/sysadmin privileges.
7. The 'xp_cmdshell' command executes as the LocalSystem user on the underlying Windows host.
8. Attacker gains full remote code execution, enabling persistence or further exfiltration.

## Impact

Successful exploitation leads to unauthenticated remote code execution with LocalSystem privileges on the server hosting the mJobTime application. This allows attackers to install persistent backdoors, exfiltrate sensitive payroll and personnel data, move laterally within the network, or deploy ransomware. As the application is often used for workforce management, the impact of a breach includes potential exposure of extensive PII and payroll information for all company employees.

## Recommendation

1. Patch mJobTime to a version beyond 15.7.3.32 immediately to address the vulnerability in Login.aspx.
2. Implement strict network segmentation to ensure the mJobTime web server is not reachable from the public internet.
3. Disable 'xp_cmdshell' and similar extended stored procedures within the Sybase SQL Anywhere configuration if they are not required for business operations.
4. Monitor web server logs for suspicious POST requests to 'Login.aspx' containing SQL-specific keywords like 'xp_cmdshell' or 'xp_read_file'.
