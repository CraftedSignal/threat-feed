---
title: Azure Storage Account Deletion Detection
slug: 2024-01-azure-storage-deletion
description: This brief detects the deletion of Azure Storage Accounts which can indicate malicious activity like data destruction, denial of service, or covering tracks after data exfiltration by adversaries.
date: "2024-01-09T18:21:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - storage
  - deletion
  - impact
vendors:
  - Microsoft
products:
  - Azure Storage Account
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1489
    technique_name: Service Stop
references:
  - https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
rules:
  - title: Azure Storage Account Deletion by Unusual User
    description: Detects deletion of Azure Storage Account by an unusual user based on Activity Logs.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
  - title: Azure Storage Account Deletion by Service Principal
    description: Detects deletion of Azure Storage Account by service principal based on Activity Logs.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
rules_count: 2
---

This detection identifies when an Azure Storage Account is deleted, a high-impact operation with significant consequences. Adversaries may delete storage accounts to disrupt operations, destroy evidence of their activities, or cause denial of service, potentially as part of ransomware or destructive attacks. Monitoring storage account deletions is crucial for detecting potential impact on business operations and data availability within Azure environments. The provided rule focuses on identifying storage account deletions performed by unusual users, leveraging Azure Activity Logs to pinpoint potentially malicious activity. The rule relies on the "MICROSOFT.STORAGE/STORAGEACCOUNTS/DELETE" operation name and user identity information.

## Attack Chain

1.  An attacker gains unauthorized access to an Azure account through compromised credentials or exploiting a vulnerability.
2.  The attacker elevates their privileges within the Azure environment to gain the necessary permissions to manage storage accounts (requires Contributor or Owner role).
3.  The attacker identifies a storage account containing sensitive data or critical application components.
4.  The attacker executes the "MICROSOFT.STORAGE/STORAGEACCOUNTS/DELETE" operation to delete the targeted storage account using an unusual user account.
5.  Azure Activity Logs record the deletion event, including details about the user, timestamp, and resource involved.
6.  The attacker attempts to cover their tracks by deleting or modifying other logs and audit trails.
7.  The deletion of the storage account causes data loss, application downtime, and disruption of business operations.

## Impact

Successful deletion of Azure Storage Accounts leads to permanent data loss, impacting business operations and application availability. The number of affected victims depends on the storage account's contents and the criticality of the applications relying on it. This activity can result in significant financial losses, reputational damage, and regulatory compliance issues. The deletion of storage accounts may be part of a larger ransomware or destructive attack targeting cloud infrastructure.

## Recommendation

*   Deploy the Sigma rule "Azure Storage Account Deletion by Unusual User" to your SIEM, using `logs-azure.activitylogs-*` index, and tune the `new_terms` field for your environment.
*   Review Azure RBAC permissions and restrict storage account deletion capabilities to authorized users only, based on the guidance in the rule documentation.
*   Configure Azure Activity Log alerts to notify security teams immediately when storage accounts are deleted, as described in the rule documentation.
*   Implement Azure Resource Locks to prevent accidental or malicious deletion of critical storage accounts, per the rule documentation.
