---
title: Multiple Azure Storage Account Deletions by User
slug: 2024-01-02-azure-storage-deletion
description: A single user or service principal deleting multiple Azure Storage Accounts within a short time period may indicate malicious activity such as data destruction, service disruption, or a ransomware attack.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - azure
  - storage
  - impact
vendors:
  - Microsoft
products:
  - Azure
  - Azure Storage Accounts
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
  - https://attack.mitre.org/techniques/T1485/
  - https://attack.mitre.org/techniques/T1489/
rules:
  - title: Azure Storage Account Deletions by User
    description: Detects when a single user or service principal deletes multiple Azure Storage Accounts within a short time period.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - azure
  - title: Azure Storage Account Deletions - Unusual User Agent
    description: Detects deletion of Azure storage accounts using a non-standard user agent, which may indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - cloudtrail
      - azure
rules_count: 2
---

This detection identifies when a single user or service principal deletes multiple Azure Storage Accounts within a short time period. This behavior can indicate an adversary attempting to cause widespread service disruption, destroy evidence, or execute a destructive attack such as ransomware. Mass deletion of storage accounts can have severe business impact and is rarely performed by legitimate administrators except during controlled decommissioning activities. The original Elastic detection rule was published on 2025/10/08 and updated on 2026/04/10. This threat is important for defenders because Azure Storage Accounts are critical infrastructure components that store application data, backups, and business-critical information.

## Attack Chain

1. An attacker gains unauthorized access to an Azure account or service principal.
2. The attacker enumerates available Azure Storage Accounts within the subscription.
3. The attacker uses the Azure portal, CLI, or API to initiate deletion of multiple storage accounts.
4. Azure Activity Logs record the "MICROSOFT.STORAGE/STORAGEACCOUNTS/DELETE" operations.
5. The attacker attempts to disable or delete backups to hinder recovery efforts.
6. If successful, the deletion of storage accounts results in data loss and service disruption.
7. The attacker may attempt to exfiltrate additional data before final deletion.
8. The attack aims to cause maximum impact by deleting as many storage accounts as possible in a short timeframe.

## Impact

Mass deletion of storage accounts can result in significant data loss, service disruption, and financial damage. The number of affected storage accounts can vary, but the impact is generally high due to the critical nature of stored data. This attack could impact any organization using Azure Storage Accounts, including those in the technology, finance, and healthcare sectors. If successful, organizations may experience data breaches, compliance violations, and reputational damage.

## Recommendation

*   Deploy the Sigma rule "Azure Storage Account Deletions by User" to your SIEM and tune for your environment.
*   Review Azure Activity Logs for the "MICROSOFT.STORAGE/STORAGEACCOUNTS/DELETE" operation to investigate potential mass deletion attempts.
*   Implement Azure Resource Locks on all critical storage accounts to prevent accidental or malicious deletion.
*   Configure Azure Policy to require approval workflows for storage account deletions using Azure Blueprints or custom governance solutions.
*   Enable Azure Activity Log alerts to notify security teams immediately when storage accounts are deleted.
