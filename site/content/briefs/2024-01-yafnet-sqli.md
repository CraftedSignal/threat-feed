---
title: YAFNET Pre-Handler Authorization Bypass Leads to SQL Injection
slug: 2024-01-yafnet-sqli
description: YAFNET's flawed authorization allows low-privileged users to execute arbitrary SQL commands via the `/Admin/RunSql` endpoint, potentially leading to data exfiltration, application modification, and denial-of-service.
date: "2024-01-03T18:21:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - web-application
  - vulnerability
vendors:
  - Microsoft
products:
  - YAFNET.Core (<= 4.0.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505.003
    technique_name: 'Server Software Component: Web Shell'
references:
  - https://github.com/advisories/GHSA-xhw7-j96h-c3g5
rules:
  - title: Detect YAFNET SQL Injection Attempt
    description: Detects potential SQL injection attempts against the YAFNET /Admin/RunSql endpoint using time-based injection techniques.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1190
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Detect Potential YAFNET Admin Page Access Attempt by Non-Admin
    description: Detects attempts to access the YAFNET admin pages by non-admin users, which should be investigated further.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

YAFNET, a forum software, contains a critical vulnerability (CVE-2026-43937) related to its administrative authorization process. The `PageSecurityCheckAttribute`, intended to restrict access to admin functions, executes after the page handler, failing to prevent unauthorized actions. This flaw allows even low-privileged, registered users to access the `/Admin/RunSql` endpoint, which directly passes user-supplied input to the `IDbAccess.RunSql` function without proper validation. This results in blind SQL injection, allowing attackers to execute arbitrary SQL queries against the application database. The vulnerability affects YAFNET Core versions 4.0.4 and earlier. Exploitation is straightforward, requiring only a registered forum account and a single HTTP POST request, making it highly likely to be exploited.

## Attack Chain

1.  A low-privileged user registers or logs into the YAFNET forum.
2.  The user obtains a valid `__RequestVerificationToken` and session cookies from any rendered page.
3.  The attacker crafts a malicious HTTP POST request to `/Admin/RunSql?handler=RunQuery`.
4.  The POST request includes a URL-encoded SQL payload in the `Editor` parameter, designed for blind SQL injection.
5.  The `PageSecurityCheckAttribute` fails to prevent execution of the `OnPostRunQuery` handler due to its late execution timing.
6.  The `OnPostRunQuery` handler passes the unsanitized `Editor` value directly to `IDbAccess.RunSql`.
7.  The attacker uses a time-based SQL injection technique, such as `WAITFOR DELAY`, to determine the output of SQL queries.
8.  The attacker exfiltrates sensitive data, modifies forum data, or performs a denial-of-service attack by manipulating the database.

## Impact

Successful exploitation allows attackers with minimal privileges to gain full control over the application database, including sensitive user data, forum configurations, and identity stores. This can lead to full loss of Confidentiality, Integrity, and Availability. The impact escalates if the underlying SQL Server instance has `xp_cmdshell` or CLR integration enabled, potentially leading to OS-level command execution. Given the ease of exploitation and the severity of the potential impact, this vulnerability presents a significant risk to YAFNET deployments.

## Recommendation

*   Implement the suggested remediation from the advisory by converting `PageSecurityCheckAttribute` to an `IAsyncPageFilter` to enforce authorization before handler execution.
*   Restrict `/Admin/RunSql` access to `HostAdmin` users only and implement a statement-type allow-list on `IDbAccess.RunSql` to prevent non-read-only SQL execution.
*   Deploy the Sigma rule `Detect YAFNET SQL Injection Attempt` to identify malicious SQL payloads within HTTP POST requests to `/Admin/RunSql`.
*   Enable webserver logging to capture HTTP POST requests for analysis and detection using the provided Sigma rule.
*   Patch YAFNET to a version beyond 4.0.4 to remediate CVE-2026-43937.
