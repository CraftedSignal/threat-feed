---
title: Unusual Azure Storage Account Key Access by Privileged User
slug: 2024-01-azure-storage-key-access
description: Detects unusual access to Azure Storage Account keys by users with Owner, Contributor, Storage Account Contributor, or User Access Administrator roles, potentially indicating compromised identities as seen in STORM-0501 ransomware campaigns.
date: "2024-01-09T16:00:00Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Storm-0501
tags:
  - azure
  - storage account
  - credential access
  - ransomware
vendors:
  - Microsoft
products:
  - Microsoft Azure
  - Azure Storage Accounts
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
  - https://docs.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage
rules:
  - title: Azure Storage Account Keys Accessed by Privileged User - New Access
    description: Detects first-time access to Azure Storage Account keys within 7 days by privileged users (Owner, Contributor, Storage Account Contributor, User Access Administrator).
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1078.004
      - T1555.006
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
  - title: Azure Storage Account Keys Accessed - All Accesses
    description: Detects all access to Azure Storage Account keys by privileged users. Use in conjunction with the new access rule for broader visibility
    platform: sigma
    severity: low
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1078.004
      - T1555.006
    data_sources:
      - cloudtrail
      - azure
      - activitylogs
rules_count: 2
---

This threat brief focuses on the detection of unusual access patterns to Azure Storage Account keys, specifically by users holding high-privilege roles such as Owner, Contributor, Storage Account Contributor, or User Access Administrator. The access of these keys allows for full administrative control over the storage resources. Microsoft recommends using Shared Access Signature (SAS) models instead of direct key access for improved security. This behavior was observed in STORM-0501 ransomware campaigns, where compromised identities with elevated Azure RBAC roles retrieved storage account keys to conduct unauthorized operations on the storage accounts. The detection strategy focuses on identifying when a user principal with these high-privilege roles accesses storage keys for the first time within a 7-day window, highlighting potentially malicious or anomalous behavior.

## Attack Chain

1.  Initial compromise of a user account with a high-privilege Azure RBAC role (Owner, Contributor, Storage Account Contributor, or User Access Administrator). This may be achieved through phishing or credential stuffing.
2.  The compromised account logs into the Azure portal or uses Azure CLI/PowerShell with valid credentials.
3.  Attacker enumerates available Azure Storage Accounts within the subscription.
4.  Using the compromised account, the attacker executes the `MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION` operation to retrieve the storage account keys.
5.  The attacker uses the retrieved storage account keys to perform unauthorized actions on the Storage Account, such as reading, modifying, or deleting data.
6.  Data exfiltration occurs using the compromised storage account keys, potentially involving tools like AzCopy or custom scripts.
7.  The attacker may attempt to move laterally to other storage accounts or Azure resources using the compromised keys.
8.  Ransomware deployment within the storage account, encrypting data and demanding payment for its recovery, as observed in STORM-0501 campaigns.

## Impact

A successful attack can lead to unauthorized data access, modification, or deletion within Azure Storage Accounts. The impact includes potential data breaches, financial losses, and reputational damage. As observed with STORM-0501, compromised storage account keys can facilitate ransomware deployment, rendering critical data inaccessible until a ransom is paid. Organizations in all sectors that utilize Azure Storage Accounts are potentially vulnerable. The compromise can allow attackers full control over the storage account leading to complete data loss.

## Recommendation

*   Implement the Sigma rule "Azure Storage Account Keys Accessed by Privileged User - New Access" to detect first-time key access within 7 days by privileged users based on `azure.activitylogs.operation_name: "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION"` and `event.outcome: "success"`.
*   Enable Azure Activity Logs and ensure they are being ingested into your SIEM to provide the data source necessary for the provided Sigma rules.
*   Rotate storage account keys immediately upon detection of unauthorized access and audit recent activities on the affected storage accounts.
*   Enforce the use of Azure AD authentication or SAS tokens instead of storage account keys to reduce future risks, as recommended by Microsoft.
*   Review and restrict the assignment of high-privilege roles like Owner and Contributor, following the principle of least privilege.
*   Configure Azure Policy to restrict the `listKeys` operation to specific roles or require additional approval workflows.
