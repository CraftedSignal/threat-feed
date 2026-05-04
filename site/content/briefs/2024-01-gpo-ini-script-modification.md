---
title: GPO Modification to Add Startup/Logon Scripts
slug: 2024-01-gpo-ini-script-modification
description: This rule detects the modification of Group Policy Objects (GPO) to add a startup or logon script to user or computer objects, enabling attackers to achieve privilege escalation and persistence by executing arbitrary commands at scale.
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
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1484
    technique_name: Domain or Tenant Policy Modification
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1037
    technique_name: Boot or Logon Initialization Scripts
references:
  - https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0025_windows_audit_directory_service_changes.md
  - https://github.com/atc-project/atc-data/blob/f2bbb51ecf68e2c9f488e3c70dcdd3df51d2a46b/docs/Logging_Policies/LP_0029_windows_audit_detailed_file_share.md
  - https://labs.f-secure.com/tools/sharpgpoabuse
rules:
  - title: Detect GPO Modification for Startup/Logon Scripts
    description: Detects modifications to Group Policy Objects (GPOs) that add or modify startup/logon scripts.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1484.001
      - T1547.001
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Creation via GPO Script
    description: Detects the creation of suspicious processes triggered by a GPO script, indicating potential malicious activity.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1059.001
      - T1547.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may abuse Group Policy Objects (GPOs) to execute malicious commands at startup, logon, shutdown, and logoff by modifying the `scripts.ini` or `psscripts.ini` files. This involves adding or modifying these files within the `<GPOPath>\\Machine\\Scripts\\` or `<GPOPath>\\User\\Scripts\\` directories. Such modifications can lead to privilege escalation by running commands with elevated privileges when users log on or systems start. Successful exploitation allows the attacker to maintain persistent access and control over the targeted systems within the Active Directory environment. This activity is often used in post-exploitation scenarios after initial access has been gained through other means, such as phishing or exploiting vulnerabilities. The goal is to achieve widespread command execution across multiple systems within the domain.

## Attack Chain

1. An attacker gains initial access to a system with sufficient privileges to modify GPOs, often through compromised credentials or exploiting a vulnerability.
2. The attacker identifies a target GPO to modify, typically one that applies to a large number of users or computers.
3. The attacker modifies either the `scripts.ini` or `psscripts.ini` file within the `Machine\\Scripts` or `User\\Scripts` directory of the targeted GPO.
4. The modification involves adding a new script entry or modifying an existing one to point to a malicious script or command. This script can be a batch file, PowerShell script, or executable.
5. The attacker links the GPO to an Organizational Unit (OU) containing the target computers or users, or modifies the existing GPO link.
6. When targeted users log on or computers start up, the GPO settings are applied, and the malicious script is executed.
7. The malicious script performs actions such as installing malware, adding user accounts with elevated privileges, or modifying system configurations.
8. The attacker achieves persistence and/or elevated privileges across the targeted systems, enabling further malicious activities.

## Impact

Successful exploitation allows attackers to execute arbitrary commands with elevated privileges across numerous systems within the targeted domain. This can result in widespread malware infection, data theft, or complete system compromise. The impact can range from operational disruption to significant financial loss and reputational damage, affecting potentially hundreds or thousands of machines. Since this attack leverages legitimate Active Directory functionalities, detection can be challenging without proper monitoring and alerting mechanisms in place.

## Recommendation

*   Enable "Audit Directory Service Changes" and "Audit Detailed File Share" Windows audit policies to generate the events required for detection, as described in the [setup instructions](https://ela.st/audit-directory-service-changes) and [audit detailed file share instructions](https://ela.st/audit-detailed-file-share).
*   Deploy the Sigma rule "Detect GPO Modification for Startup/Logon Scripts" to your SIEM to detect modifications to GPOs that add or modify startup/logon scripts.
*   Monitor Windows Security Event Logs for Event IDs 5136 and 5145 related to GPO modifications.
*   Regularly review GPO settings to identify any unauthorized or suspicious scripts.
