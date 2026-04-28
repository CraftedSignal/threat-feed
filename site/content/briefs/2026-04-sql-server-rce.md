---
title: SQL Server Untrusted Pointer Dereference Vulnerability (CVE-2026-33120)
slug: 2026-04-sql-server-rce
description: CVE-2026-33120 is an untrusted pointer dereference vulnerability in Microsoft SQL Server that allows an authenticated attacker to achieve remote code execution over a network.
date: "2026-04-15T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - sql-server
  - rce
  - vulnerability
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-33120
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33120
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33120
iocs:
  - type: email
    value: '[email protected]'
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 2
rules:
  - title: Detect Suspicious SQL Server Process Creation
    description: Detects suspicious process creation events originating from SQL Server processes, potentially indicating exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect SQL Server Network Activity on Non-Standard Ports
    description: Detects network connections to SQL Server processes on ports other than the default port 1433, which could indicate malicious activity or misconfiguration.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-33120 is a critical vulnerability affecting Microsoft SQL Server. This vulnerability, classified as an untrusted pointer dereference, allows an authorized attacker to execute arbitrary code on the targeted system remotely. Successful exploitation requires the attacker to be authenticated to the SQL Server instance, reducing the attack surface but still posing a significant threat to internal networks. The vulnerability was reported by Microsoft and assigned a CVSS v3.1 score of 8.8, highlighting its potential for significant impact. The vulnerability poses a significant risk to organizations utilizing vulnerable SQL Server instances, as it could lead to data breaches, system compromise, and further lateral movement within the network. Defenders need to identify and patch vulnerable SQL Server instances promptly to mitigate this risk.

## Attack Chain

1.  Attacker authenticates to the targeted SQL Server instance using compromised or valid credentials.
2.  Attacker crafts a malicious SQL query designed to trigger the untrusted pointer dereference.
3.  The malicious query is sent to the SQL Server instance for processing.
4.  SQL Server attempts to dereference a pointer controlled by the attacker due to the crafted query.
5.  This dereference leads to an exception or crash within the SQL Server process.
6.  The attacker leverages this crash to gain control of the execution flow.
7.  The attacker injects malicious code into the SQL Server process memory.
8.  The injected code is executed within the context of the SQL Server service account, granting the attacker system-level privileges and remote code execution.

## Impact

Successful exploitation of CVE-2026-33120 allows an authenticated attacker to execute arbitrary code on the targeted SQL Server instance with system-level privileges. This can lead to complete system compromise, data breaches, denial of service, and further lateral movement within the network. The vulnerability affects all SQL Server versions prior to the patch. Given the widespread use of SQL Server in enterprise environments, a successful exploit could have significant repercussions, impacting sensitive data and critical business operations.

## Recommendation

*   Apply the security update released by Microsoft to patch CVE-2026-33120 on all affected SQL Server instances immediately. Refer to the Microsoft advisory (https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-33120) for specific instructions.
*   Monitor SQL Server logs for suspicious activity, such as unexpected crashes or unusual query patterns that might indicate exploitation attempts. Create a rule based on process creation with unexpected parent processes.
*   Implement the Sigma rule `Detect Suspicious SQL Server Process Creation` to detect potential exploitation attempts based on process creation events.
*   Review and enforce the principle of least privilege for SQL Server accounts to minimize the impact of successful exploitation.
