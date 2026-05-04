---
title: GPO Scheduled Task Abuse for Privilege Escalation and Lateral Movement
slug: 2024-01-gpo-scheduled-task-abuse
description: Attackers abuse Group Policy Objects by modifying scheduled task attributes to execute malicious commands across objects controlled by the GPO, potentially leading to privilege escalation and lateral movement.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - group-policy
  - scheduled-task
  - privilege-escalation
  - lateral-movement
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1053
    technique_name: Scheduled Task/Job
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1484
    technique_name: Domain or Tenant Policy Modification
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1570
    technique_name: Lateral Tool Transfer
references:
  - https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0025_windows_audit_directory_service_changes.md
  - https://github.com/atc-project/atc-data/blob/f2bbb51ecf68e2c9f488e3c70dcdd3df51d2a46b/docs/Logging_Policies/LP_0029_windows_audit_detailed_file_share.md
  - https://labs.f-secure.com/tools/sharpgpoabuse
  - https://twitter.com/menasec1/status/1106899890377052160
  - https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_gpo_scheduledtasks.yml
rules:
  - title: Scheduled Task Execution via GPO Attribute Modification
    description: Detects modifications to Group Policy Object attributes related to scheduled task extensions.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
      - privilege_escalation
    techniques:
      - T1053.005
      - T1484.001
    data_sources:
      - process_creation
      - windows
  - title: Scheduled Task XML File Modification in SYSVOL
    description: Detects modifications to the ScheduledTasks.xml file within the SYSVOL share, indicating potential GPO abuse.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
      - privilege_escalation
    techniques:
      - T1053.005
      - T1484.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Attackers can abuse Group Policy Objects (GPOs) to execute scheduled tasks at scale, compromising objects controlled by a given GPO. This involves modifying the contents of the `<GPOPath>\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml` file. By altering the XML file to include malicious commands, attackers can achieve privilege escalation or lateral movement within the domain. This technique leverages a legitimate Active Directory mechanism, making it essential to differentiate between authorized administrative actions and malicious activities. The modification can be identified through changes to `gPCMachineExtensionNames` or `gPCUserExtensionNames` attributes within Active Directory.

## Attack Chain

1.  Attacker gains initial access to a system with permissions to modify GPOs.
2.  Attacker modifies the `ScheduledTasks.xml` file within the SYSVOL share of a targeted GPO (`\\\\*\\SYSVOL`).
3.  The attacker changes the contents of the XML file to include a malicious `<Command>` and `<Arguments>` tag.
4.  The modified GPO is replicated to domain controllers.
5.  Target systems receive the updated GPO during regular group policy refresh cycles.
6.  The scheduled task defined in the modified `ScheduledTasks.xml` is executed on the target systems.
7.  The malicious command executes, potentially escalating privileges or facilitating lateral movement.
8.  Attacker achieves desired objective, such as installing malware, creating new accounts, or exfiltrating data.

## Impact

Successful exploitation allows attackers to execute arbitrary code on systems managed by the modified GPO. The scope of impact depends on the targeted GPO and the permissions of the scheduled task. This can lead to widespread compromise, affecting numerous systems and users within the domain. The modification of GPOs can be difficult to detect without proper monitoring, potentially allowing attackers to maintain persistence and control over the environment.

## Recommendation

*   Enable and monitor Windows audit policies for "Audit Directory Service Changes" and "Audit Detailed File Share" to detect modifications to GPOs and file share access, as outlined in the [setup](#setup) section.
*   Deploy the Sigma rule "Scheduled Task Execution via GPO Attribute Modification" to detect modifications to the `gPCMachineExtensionNames` or `gPCUserExtensionNames` attributes (rule: `Scheduled Task Execution via GPO Attribute Modification`).
*   Deploy the Sigma rule "Scheduled Task XML File Modification in SYSVOL" to detect modifications to the ScheduledTasks.xml file in SYSVOL shares (rule: `Scheduled Task XML File Modification in SYSVOL`).
*   Review and validate any changes to GPOs, specifically those related to scheduled tasks, to ensure they are authorized and legitimate.
*   Monitor for the execution of unexpected or malicious commands originating from scheduled tasks created or modified via GPOs.
*   Regularly audit and review GPO configurations to identify any potential weaknesses or misconfigurations that could be exploited.
