---
title: Azure RBAC Built-In Administrator Role Assignment
slug: 2024-01-azure-rbac-privilege-escalation
description: Detection of a user being assigned a built-in administrator role in Azure RBAC, which can be abused for privilege escalation, lateral movement, or persistence.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - rbac
  - privilege-escalation
  - persistence
vendors:
  - Microsoft
products:
  - Azure
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
  - https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
  - https://orca.security/resources/research-pod/azure-identity-access-management-iam-active-directory-ad/
  - https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
rules:
  - title: Azure RBAC Built-In Administrator Roles Assigned
    description: Detects when a user is assigned a built-in administrator role in Azure RBAC.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - cloudtrail
      - azure
      - activitylog
  - title: Azure RBAC Role Assignment via Azure CLI
    description: Detects Azure RBAC role assignments performed using the Azure CLI.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This alert identifies when a user is assigned a built-in administrator role within Azure Role-Based Access Control (RBAC). These roles grant significant permissions and attackers can potentially exploit them for lateral movement, establishing persistence, or escalating their privileges within the Azure environment. The built-in roles covered by this alert are Owner, Contributor, User Access Administrator, Azure File Sync Administrator, Reservations Administrator, and Role Based Access Control Administrator. Assignments can occur through the Azure portal, CLI, PowerShell, or API calls. Monitoring these assignments is crucial for identifying and preventing unauthorized privilege escalation attempts, especially from compromised accounts or malicious insiders.

## Attack Chain

1.  An attacker gains initial access to an Azure account, potentially through compromised credentials or a vulnerability.
2.  The attacker enumerates existing roles and permissions within the Azure environment to identify potential targets for privilege escalation.
3.  The attacker uses their existing (limited) permissions to attempt to assign a built-in administrator role (Owner, Contributor, etc.) to a user or service principal they control. This is done through Azure portal, Azure CLI, PowerShell, or API calls.
4.  The role assignment event generates an Azure Activity Log entry with `event.action: "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"` and relevant `roleDefinitionId`.
5.  If the role assignment is successful, the attacker now possesses the privileges associated with the assigned administrator role.
6.  The attacker leverages their newly acquired privileges to access sensitive resources, modify configurations, or deploy malicious code within the Azure environment.
7.  The attacker may create new accounts or modify existing ones to establish persistence, ensuring continued access even if their initial access is revoked.
8.  The ultimate goal may be data exfiltration, denial of service, or ransomware deployment targeting cloud resources.

## Impact

A successful privilege escalation can grant an attacker complete control over the targeted Azure subscription. This includes the ability to access and modify sensitive data, disrupt critical services, and deploy malicious workloads. Depending on the scope of the compromised subscription, this could result in significant financial losses, reputational damage, and legal liabilities. The STORM-0501 group has been known to leverage similar techniques for cloud-based ransomware attacks.

## Recommendation

*   Deploy the Sigma rule "Azure RBAC Built-In Administrator Roles Assigned" to your SIEM to detect unauthorized role assignments in real-time by monitoring Azure Activity Logs.
*   Review the investigation steps outlined in the overview if the Sigma rule is triggered.
*   Configure alerts for modifications to critical Azure resources using Azure Monitor.
*   Enforce multi-factor authentication (MFA) for all user accounts, especially those with privileged roles.
*   Implement Just-In-Time (JIT) access for privileged roles to limit the window of opportunity for attackers.
*   Regularly review and audit Azure RBAC assignments to identify and remove unnecessary privileges.
