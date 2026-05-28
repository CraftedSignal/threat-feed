---
title: SQL Server Critical Procedures Enabled Leading to Potential Code Execution or Reconnaissance
slug: 2026-05-windows-sql-server-critical-procedures
description: Modification of critical SQL Server configuration options, such as 'Ad Hoc Distributed Queries', 'external scripts enabled', 'Ole Automation Procedures', 'clr enabled', and 'clr strict security', can enable attackers to perform Active Directory reconnaissance and execute arbitrary code, potentially leading to code execution or reconnaissance activities.
date: "2026-05-28T18:01:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-server
  - code-execution
  - reconnaissance
  - windows
vendors:
  - Microsoft
  - Splunk
products:
  - SQL Server
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1505
    technique_name: Server Software Component
references:
  - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/ad-hoc-distributed-queries-server-configuration-option
  - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/external-scripts-enabled-server-configuration-option
  - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/ole-automation-procedures-server-configuration-option
  - https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/clr-enabled-server-configuration-option
  - https://www.netspi.com/blog/technical/network-penetration-testing/enumerating-domain-accounts-via-sql-server-using-adsi/
  - https://attack.mitre.org/techniques/T1505/001/
  - https://www.netspi.com/blog/technical-blog/adversary-simulation/attacking-sql-server-clr-assemblies/
rules:
  - title: Detect SQL Server Critical Procedures Enabled
    description: Detects when critical SQL Server procedures are enabled, potentially indicating malicious activity.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1505.001
    data_sources:
      - application
      - windows
  - title: Detect SQL Server Critical Procedures Disabled
    description: Detects when critical SQL Server procedures are disabled, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1505.001
    data_sources:
      - application
      - windows
rules_count: 2
---

Attackers may target SQL Server instances to enable critical procedures, providing avenues for reconnaissance and code execution. The modification of configuration options like 'Ad Hoc Distributed Queries' allows Active Directory reconnaissance via ADSI, while 'external scripts enabled' and 'Ole Automation Procedures' facilitate the execution of arbitrary code. The abuse of 'clr enabled' and 'clr strict security' can lead to running custom assemblies. Defenders should monitor for unexpected enabling of these features, as it may signal malicious actors attempting to gain a foothold, escalate privileges, or gather sensitive information within the environment. This activity leverages Event ID 15457 in the Windows Application Event Log.

## Attack Chain

1. **Initial Access:** An attacker gains initial access to a system with SQL Server installed, potentially through compromised credentials or exploiting an existing vulnerability.
2. **Privilege Escalation:** The attacker escalates privileges to a level where they can modify SQL Server configuration settings.
3. **Configuration Change:** The attacker enables one or more critical SQL Server procedures, such as "Ad Hoc Distributed Queries", "external scripts enabled", "Ole Automation Procedures", "clr enabled", or "clr strict security". This is logged as Event ID 15457.
4. **AD Reconnaissance (Ad Hoc Distributed Queries):** If "Ad Hoc Distributed Queries" is enabled, the attacker uses it to perform Active Directory reconnaissance through the ADSI provider.
5. **Code Execution (External Scripts or OLE Automation):** If "external scripts enabled" or "Ole Automation Procedures" are enabled, the attacker leverages these features to execute arbitrary code on the SQL Server instance.
6. **CLR Assembly Execution:** If "clr enabled" is enabled, the attacker can load and execute custom CLR assemblies within the SQL Server process.
7. **Data Exfiltration/Lateral Movement:** The attacker uses the compromised SQL Server to exfiltrate sensitive data or move laterally to other systems within the network.
8. **Persistence:** The attacker may establish persistence by creating scheduled jobs or other mechanisms within SQL Server that leverage the enabled procedures.

## Impact

Successful enabling of critical SQL Server procedures can allow attackers to perform reconnaissance, execute arbitrary code, and potentially compromise the entire SQL Server instance and connected systems. This can lead to data breaches, system compromise, and significant disruption of services. The impact can range from reconnaissance and data theft to complete system takeover.

## Recommendation

*   Enable Windows Application Event Log collection from SQL Server instances, ensuring Event ID 15457 is ingested for configuration changes.
*   Deploy the Sigma rule `Detect SQL Server Critical Procedures Enabled` to your SIEM to identify modifications to critical SQL Server configuration options.
*   Review and tune the rule `Detect SQL Server Critical Procedures Enabled` for false positives in your environment, considering legitimate use cases for these features.
*   Implement change control procedures for SQL Server configuration modifications to prevent unauthorized changes.
*   Investigate any alerts generated by the `Detect SQL Server Critical Procedures Enabled` Sigma rule to determine the legitimacy of the configuration change and potential malicious intent.
