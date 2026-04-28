---
title: Detection of Azure Application Deletion
slug: 2024-01-azure-app-deletion
description: This alert identifies when an application is deleted within an Azure environment, which could indicate malicious activity or unintended misconfiguration leading to service disruption.
date: "2024-01-03T15:27:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - azure
  - application
  - deletion
  - impact
  - t1489
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
references:
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities#application-proxy
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_application_deleted.yml
rules:
  - title: Azure Application Deletion Detected
    description: Detects when an application is deleted in Azure Activity Logs.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1489
    data_sources:
      - azure
      - activitylogs
  - title: Azure Application Deletion by Unusual User
    description: Detects when an application is deleted in Azure Activity Logs by an unusual user account.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1489
    data_sources:
      - azure
      - activitylogs
rules_count: 2
---

This detection focuses on identifying instances where an application is deleted within an Azure environment. While legitimate application deletions occur as part of IT administration, malicious actors might delete applications to disrupt services, remove evidence of their presence, or prepare for a larger attack by removing security controls or access points. This activity is logged within Azure Activity Logs and includes events such as "Delete application" and "Hard Delete application". Monitoring these events can provide early warning of potential security incidents or compliance violations.

## Attack Chain

1.  **Initial Access:** An attacker gains unauthorized access to an Azure account, potentially through compromised credentials or exploiting a vulnerability in an application.
2.  **Privilege Escalation (Optional):** The attacker escalates their privileges within the Azure environment to gain sufficient permissions to manage and delete applications.
3.  **Reconnaissance:** The attacker identifies target applications for deletion, potentially those critical for business operations or those used for security controls.
4.  **Disable Monitoring (Optional):** The attacker attempts to disable logging or monitoring related to application management to avoid detection.
5.  **Application Deletion:** The attacker initiates the deletion of the targeted application using the Azure portal, Azure CLI, or PowerShell.
6.  **Confirmation/Hard Delete:** Depending on the application's configuration and Azure policies, the attacker may need to confirm the deletion or perform a "hard delete" to permanently remove the application.
7.  **Cover Tracks:** The attacker attempts to remove any remaining logs or traces of their activity to hinder forensic investigation.
8.  **Impact:** Service disruption or data loss due to the deleted application.

## Impact

The deletion of an Azure application can lead to significant service disruption, data loss, and potential financial damages. The impact depends on the criticality of the deleted application and the organization's disaster recovery capabilities. Successful deletion can interrupt business processes, impacting both internal users and external customers. It may also lead to reputational damage and compliance violations if the application handled sensitive data.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect application deletion events in Azure Activity Logs.
*   Review user roles and permissions in Azure Active Directory (Entra ID) and enforce the principle of least privilege.
*   Implement multi-factor authentication (MFA) for all user accounts, especially those with administrative privileges.
*   Enable auditing and logging for all Azure resources, including application management activities.
*   Investigate any detected application deletion events promptly to determine the root cause and potential impact.
*   Establish a process for reviewing and approving application deletion requests to prevent accidental or malicious deletions.
