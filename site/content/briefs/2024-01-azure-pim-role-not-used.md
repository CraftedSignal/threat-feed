---
title: Unused Privileged Identity Management (PIM) Roles in Azure
slug: 2024-01-azure-pim-role-not-used
description: Detection of assigned but unused privileged roles in Azure's Privileged Identity Management (PIM) service, indicating potential misconfiguration, license overuse, or dormant privileged access that could be exploited.
date: "2024-01-03T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - azure
  - pim
  - privileged-identity-management
  - role-based-access-control
  - initial-access
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#administrators-arent-using-their-privileged-roles
rules:
  - title: Azure PIM - Unused Role Assignment Alert
    description: Detects when a user has been assigned a privileged role in Azure PIM but is not using that role, triggering the 'redundantAssignmentAlertIncident' event.
    platform: sigma
    severity: high
    tactics:
      - initial-access
      - privilege-escalation
    techniques:
      - T1078
    data_sources:
      - azure
      - pim
  - title: Azure PIM - Potential Dormant Account with Privileges
    description: Detects potential dormant accounts with assigned PIM roles that may be targeted by attackers.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
    data_sources:
      - azure
      - pim
rules_count: 2
---

This alert identifies a condition where users have been assigned privileged roles within Azure's Privileged Identity Management (PIM) but are not actively utilizing those roles. This situation can arise from various factors, including misconfiguration of PIM settings, over-allocation of privileged roles due to process gaps or lack of oversight, or the presence of dormant accounts with elevated privileges. Such unused roles represent a potential security risk, as they can be exploited by malicious actors or misused inadvertently, especially if MFA or conditional access policies are not enforced. Regularly auditing and addressing unused PIM roles is crucial for maintaining a strong security posture and optimizing license utilization.

## Attack Chain

1. An administrator assigns a privileged role to a user within Azure PIM.
2. The user is granted the role but does not activate or use it to perform any privileged actions.
3. Azure PIM monitors role usage and detects the lack of activity for the assigned role.
4. The "redundantAssignmentAlertIncident" event is triggered within the Azure PIM logs.
5. An attacker gains access to the user's account through credential compromise or other means.
6. The attacker activates the unused privileged role.
7. The attacker leverages the now-active privileged role to perform unauthorized actions, such as modifying system configurations, accessing sensitive data, or escalating privileges further.
8. The attacker achieves their objective, such as data exfiltration or system compromise, without being detected due to the pre-existing role assignment.

## Impact

The presence of unused privileged roles can lead to significant security breaches and compliance violations. An attacker exploiting an unused role can gain immediate access to sensitive resources and perform unauthorized actions, potentially leading to data breaches, system outages, or financial losses. The number of affected users and resources depends on the scope of the unused role and the attacker's objectives. Failure to identify and address these unused roles can also result in unnecessary license costs and increased attack surface.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect `redundantAssignmentAlertIncident` events indicating unused PIM roles in Azure (see "Roles Are Not Being Used" rule).
*   Investigate all detected instances of unused PIM roles to determine the reason for inactivity and potential risks.
*   Revoke the assigned role if the user no longer requires it, or provide training and guidance to ensure proper role utilization.
*   Review and refine PIM role assignment policies to minimize the allocation of unnecessary privileges.
*   Implement regular audits of PIM role assignments to identify and address unused roles promptly.
*   Configure security alerts within Azure PIM to receive notifications about unused roles and other potential security incidents.
