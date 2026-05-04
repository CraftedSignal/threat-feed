---
title: GPO Scheduled Task or Service Creation/Modification
slug: 2024-01-gpo-scheduled-task-modification
description: Detection of the creation or modification of new Group Policy based scheduled tasks or services, which can be abused by attackers with domain admin permissions to execute malicious payloads remotely on domain-joined machines, leading to privilege escalation and persistence.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - group-policy
  - privilege-escalation
  - persistence
  - windows
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
products:
  - Elastic Defend
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1484
    technique_name: Domain or Tenant Policy Modification
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://attack.mitre.org/techniques/T1484/
  - https://attack.mitre.org/techniques/T1053/
  - https://attack.mitre.org/techniques/T1543/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/privilege_escalation_gpo_schtask_service_creation.toml
rules:
  - title: Detect GPO Scheduled Task/Service Modification via File Event
    description: Detects modifications to ScheduledTasks.xml or Services.xml within Group Policy paths, excluding dfsrs.exe, indicating potential malicious GPO-based attacks.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1053.005
      - T1484.001
      - T1543.003
    data_sources:
      - file_event
      - windows
  - title: Detect GPO Scheduled Task/Service Creation via Process Creation
    description: Detects the creation of scheduled tasks or services via command-line tools within Group Policy paths, indicating potential malicious GPO-based attacks.
    platform: sigma
    severity: low
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1053.005
      - T1484.001
      - T1543.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers with domain administrator privileges can abuse Group Policy Objects (GPOs) to deploy malicious payloads across a Windows domain. By creating or modifying scheduled tasks or services via GPOs, an attacker can achieve both privilege escalation and persistence. This involves modifying files such as `ScheduledTasks.xml` or `Services.xml` within the SYSVOL share. The modifications are replicated to domain-joined machines when the GPO is applied. This technique allows for remote code execution and control over a significant number of systems from a central point, making it a powerful tool for adversaries targeting enterprise environments. The described rule detects file modifications within specific GPO paths, excluding changes made by the `dfsrs.exe` process to reduce false positives. The rule is designed to detect suspicious activities related to scheduled tasks and services within Group Policy settings, helping security teams identify and respond to potential threats originating from compromised domain administrator accounts.

## Attack Chain

1.  Attacker gains domain administrator privileges through compromised credentials or exploiting a vulnerability.
2.  Attacker navigates to the SYSVOL share, typically located at `\\<domain>\SYSVOL\<domain>\Policies\`.
3.  Attacker identifies a GPO to modify or creates a new GPO.
4.  Attacker modifies the `ScheduledTasks.xml` or `Services.xml` file within the GPO's directory (`<GPO_GUID>\MACHINE\Preferences\ScheduledTasks\` or `<GPO_GUID>\MACHINE\Preferences\Services\`).
5.  The modified XML file contains instructions to create a scheduled task or service that executes a malicious payload.
6.  The Group Policy Management Console (GPMC) or other tools are used to link the GPO to an organizational unit (OU) containing target computers.
7.  Target machines within the OU receive the updated GPO settings during the next Group Policy refresh cycle (or forced via `gpupdate /force`).
8.  The scheduled task or service is created on the target machine, executing the attacker's malicious payload and achieving persistence or privilege escalation.

## Impact

A successful attack can lead to widespread compromise across the domain. Attackers can execute arbitrary code on numerous systems, potentially leading to data exfiltration, ransomware deployment, or disruption of critical services. The impact can range from minor inconveniences to complete operational shutdown, depending on the nature of the malicious payload and the attacker's objectives. Without proper detection and response mechanisms, such attacks can persist for extended periods, causing significant damage to the organization.

## Recommendation

*   Deploy the Sigma rule `Detect GPO Scheduled Task/Service Modification via File Event` to detect unauthorized modifications to `ScheduledTasks.xml` and `Services.xml` files within GPO paths.
*   Enable Sysmon file creation and modification logging to provide the necessary data for the Sigma rules to function effectively.
*   Review and harden GPO management access controls to limit the potential for abuse by compromised accounts, based on the observed T1484.001 technique.
*   Investigate any alerts generated by the deployed rules, focusing on the user accounts and processes involved in the file modifications as described in the overview.
*   Monitor for process execution from unusual locations based on service creation or scheduled task as described in the TTPs.
