---
title: Group Policy Abuse for Privilege Addition
slug: 2026-05-group-policy-privilege-addition
description: Detects modifications to Group Policy Object Attributes that grant privileges to user accounts or add users as local administrators, indicating potential privilege escalation attempts.
date: "2026-05-12T19:00:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - group-policy
  - privilege-escalation
  - windows
vendors:
  - Microsoft
products:
  - Active Directory
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1484
    technique_name: Domain Policy Modification
references:
  - https://github.com/atc-project/atc-data/blob/master/docs/Logging_Policies/LP_0025_windows_audit_directory_service_changes.md
  - https://labs.withsecure.com/tools/sharpgpoabuse
rules:
  - title: Detect Group Policy Abuse for Privilege Addition
    description: Detects modifications to Group Policy Object Attributes to add privileges to user accounts or add users as local admins by detecting event code 5136 with specific GUIDs associated with Security CSE and Computer Restricted Groups.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1484.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Privileged Group Additions via GPO
    description: Detects changes to Group Policy Objects that add users to privileged groups using event code 5136.  This rule requires 'Audit Directory Service Changes' to be enabled.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1484.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies potential privilege escalation attempts through the modification of Group Policy Objects (GPOs). Attackers may abuse GPOs to add privileges to user accounts or add users as local administrators. This is achieved by modifying specific attributes within the GPO that control security settings. The rule focuses on detecting the initial modification of GPO attributes related to machine extension names, specifically those associated with security configuration and restricted groups. The successful exploitation of this technique can allow attackers to gain elevated privileges within the domain, potentially leading to complete domain compromise. The rule leverages Windows Security Event Logs (event code 5136) to monitor changes to GPO attributes and flags suspicious modifications. This detection is crucial for identifying and responding to potential privilege escalation attempts within an Active Directory environment.

## Attack Chain

1.  Attacker gains initial access to a system with sufficient privileges to modify GPOs. This may be achieved through compromised credentials or exploiting vulnerabilities.
2.  The attacker identifies a target GPO to modify. This GPO may be linked to a specific organizational unit (OU) or the entire domain.
3.  The attacker modifies the `gPCMachineExtensionNames` attribute of the target GPO to include the Security Configuration Engine (SCE) and Computer Restricted Groups (CRG) extensions, identified by GUIDs `827D319E-6EAC-11D2-A4EA-00C04F79F83A` and `803E14A0-B4FB-11D0-A0D0-00A0C90F574B`, respectively.
4.  The attacker modifies the `GptTmpl.inf` file within the SYSVOL folder associated with the modified GPO. This file defines the security settings enforced by the GPO.
5.  Within the `GptTmpl.inf` file, the attacker modifies the `[Privilege Rights]` section to grant high-impact privileges (e.g., SeDebugPrivilege, SeTakeOwnershipPrivilege) to target user accounts or groups.
6.  Alternatively, the attacker modifies the `[Group Membership]` section of the `GptTmpl.inf` file to add target user accounts or groups to the local Administrators group (S-1-5-32-544) on affected systems.
7.  The modified GPO is applied to the target systems through normal Group Policy update processes. This may occur automatically or be triggered manually using `gpupdate /force`.
8.  The target user accounts or groups now possess the elevated privileges or local administrator rights granted by the modified GPO, enabling the attacker to perform malicious activities on the affected systems.

## Impact

Successful exploitation allows attackers to gain elevated privileges within the Active Directory environment. This can lead to the compromise of sensitive data, the installation of malware, or the disruption of critical business operations. The scope of the impact depends on the scope of the modified GPO, potentially affecting a small number of systems or the entire domain. Privilege escalation via GPO manipulation can be difficult to detect and remediate, making it a significant threat to organizations relying on Active Directory for identity and access management.

## Recommendation

*   Enable "Audit Directory Service Changes" and monitor event code 5136 in Windows Security Event Logs as referenced in the [setup instructions](https://ela.st/audit-directory-service-changes) to ensure the necessary logs are available for detection.
*   Deploy the Sigma rule "Detect Group Policy Abuse for Privilege Addition" to your SIEM to detect suspicious modifications to GPO attributes.
*   Investigate any alerts generated by the rule, focusing on the user accounts making the changes, the target GPOs being modified, and the specific privileges being granted as described in the [Triage and Analysis section](#triage-and-analysis).
*   Regularly review GPO permissions and membership to identify and remediate any unauthorized modifications.
*   Implement the hardening steps recommended in the [Response and Remediation section](#response-and-remediation) to restrict GPO edit rights to dedicated admin tiers.
