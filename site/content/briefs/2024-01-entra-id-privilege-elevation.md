---
title: Entra ID Privilege Escalation to User Access Administrator
slug: 2024-01-entra-id-privilege-elevation
description: A user has elevated their access to User Access Administrator for their Azure Resources, potentially leading to privilege escalation and unauthorized access; this activity is flagged only if the user hasn't performed it in the last 14 days.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - entra_id
  - privilege_escalation
vendors:
  - Microsoft
products:
  - Microsoft Azure
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin?tabs=azure-portal%2Centra-audit-logs/
  - https://permiso.io/blog/azures-apex-permissions-elevate-access-the-logs-security-teams-overlook
  - https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
rules:
  - title: Entra ID User Access Administrator Elevation
    description: Detects when a user elevates their access to User Access Administrator role, potentially indicating privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - auditlogs
      - azure
  - title: Entra ID Elevated Access to User Access Administrator
    description: Alerts when elevateAccess action is detected in Entra ID audit logs, which indicates a user has elevated their access to User Access Administrator.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - auditlogs
      - azure
rules_count: 2
---

This threat brief addresses the elevation of user privileges to "User Access Administrator" within Azure/Entra ID environments. The User Access Administrator role grants extensive control over user access to Azure resources, enabling role assignments and permission management. While legitimate use cases exist, adversaries may exploit this role to gain unauthorized access to sensitive data and escalate privileges further. The detection rule focuses on identifying anomalous behavior by flagging instances where a user elevates their access to User Access Administrator for the first time in 14 days. This helps filter out routine administrative tasks and highlights potentially malicious activity. The activity is tracked via Azure Audit Logs and is related to Microsoft.Authorization/elevateAccess/action API calls. The Storm-0501 group has been observed using similar techniques as of August 2025 to achieve cloud-based ransomware deployment.

## Attack Chain

1. Initial access to an Entra ID account with sufficient privileges (e.g., Global Administrator).
2. The attacker authenticates to the Azure portal or uses Azure CLI with compromised credentials.
3. The attacker executes a request to elevate their account's privileges to "User Access Administrator." This often involves calling the `Microsoft.Authorization/elevateAccess/action` API.
4. Azure Audit Logs record the successful elevation of privileges.
5. The attacker leverages the User Access Administrator role to assign themselves additional, more granular roles (e.g., Contributor, Owner) on specific Azure resources.
6. The attacker uses these newly acquired roles to access sensitive data, modify configurations, or deploy malicious code within the Azure environment.
7. The attacker might attempt to disable security controls or create persistent backdoors for future access.
8. The attacker achieves their final objective, such as data exfiltration, resource disruption, or ransomware deployment.

## Impact

Successful exploitation can grant an attacker full control over access management within the Azure environment. This may lead to widespread data breaches, service disruption, and financial losses. The "User Access Administrator" role enables attackers to assign roles and permissions, granting them access to sensitive resources. This activity can lead to lateral movement, persistence, or privilege escalation. As seen with groups like Storm-0501, cloud environments are increasingly targeted for ransomware attacks, and this type of privilege escalation is often a critical step.

## Recommendation

*   Deploy the Sigma rule `Entra ID User Access Administrator Elevation` to detect the initial privilege escalation activity (Azure Audit Logs).
*   Review and tune the Sigma rule, `Entra ID Elevated Access to User Access Administrator` for your environment, considering legitimate administrative activities (Azure Audit Logs).
*   Implement multi-factor authentication (MFA) for all user accounts, especially those with privileged roles.
*   Monitor Azure Audit Logs for unusual activity related to role assignments and permission changes.
*   Review conditional access and PIM (Privileged Identity Management) configurations to limit elevation without approval.
*   Add alerts for repeated or unusual use of `Microsoft.Authorization/elevateAccess/action` as recommended in the original report.
