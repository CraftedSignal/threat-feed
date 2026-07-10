---
title: Azure Storage Account Blob Public Access Enabled
slug: 2024-01-azure-blob-public-access
description: Detection of Azure Storage Account Blob public access being enabled, potentially allowing external access to blob containers for data exfiltration, as abused by threat actors modifying storage account settings.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - storage
  - data_exfiltration
  - cloud_security
vendors:
  - Microsoft
products:
  - Azure Storage Account
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
references:
  - https://www.microsoft.com/en-us/security/blog/2025/08/27/storm-0501s-evolving-techniques-lead-to-cloud-based-ransomware/
  - https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure
rules:
  - title: Azure Storage Account Public Blob Access Enabled
    description: Detects when Azure Storage Account Blob public access is enabled.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - azure
      - activitylog
  - title: Azure Storage Account Modified by Unusual User Agent
    description: Detects modifications to Azure Storage Accounts made by unusual user agents, potentially indicating malicious activity.
    platform: sigma
    severity: low
    tactics:
      - collection
    techniques:
      - T1530
    data_sources:
      - cloudtrail
      - azure
      - activitylog
rules_count: 2
---

This alert focuses on detecting the enabling of public access to Azure Storage Account Blobs. This configuration change allows anonymous internet access to blob containers, bypassing typical authentication requirements. The activity is detected by monitoring for the Microsoft.Storage/storageAccounts/write operation within Azure Activity Logs.  Observed in cloud ransom-based campaigns, threat actors such as STORM-0501 have exploited this misconfiguration to expose data for exfiltration. Detecting this behavior is critical to prevent unauthorized data access and potential ransomware attacks, particularly when sensitive information is stored within Azure Blob storage.  The rule specifically looks for modifications where the `allowBlobPublicAccess` property is set to `true`.

## Attack Chain

1. **Initial Compromise:** The attacker gains initial access to an Azure account, potentially through compromised credentials or a vulnerable application.
2. **Privilege Escalation (if needed):** The attacker escalates privileges within the Azure environment to gain the necessary permissions to modify storage account settings.
3. **Storage Account Discovery:** The attacker identifies target storage accounts containing valuable data.
4. **Modify Storage Account Configuration:** The attacker executes the `Microsoft.Storage/storageAccounts/write` operation to modify the storage account's public access settings, specifically setting `allowBlobPublicAccess` to `true`.
5. **Data Exfiltration:** Once public access is enabled, the attacker accesses and exfiltrates the data stored in blob containers without needing authentication.
6. **Lateral Movement (optional):** The attacker leverages the compromised storage account to gain access to other resources within the Azure environment.
7. **Ransom/Extortion (in some cases):** The attacker encrypts the data in the storage account and demands a ransom for its recovery, or threatens to release the exfiltrated data publicly.

## Impact

Enabling public access to Azure Storage Account Blobs can lead to significant data breaches and financial losses.  Successful attacks can result in the exposure of sensitive customer data, intellectual property, or confidential business information.  The STORM-0501 campaign demonstrates how this vulnerability can be exploited in cloud ransom-based campaigns.  The impact can range from reputational damage and regulatory fines to significant operational disruptions.  The number of affected records could be substantial depending on the size and content of the exposed blob containers.

## Recommendation

*   Deploy the Sigma rule `Azure Storage Account Public Blob Access Enabled` to your SIEM to detect unauthorized modifications to storage account access settings.
*   Implement Azure Policy to prevent enabling public blob access on storage accounts containing sensitive data as described in the overview.
*   Review Azure activity logs for any instances of `Microsoft.Storage/storageAccounts/write` events as outlined in the attack chain to identify potential unauthorized changes.
*   Audit all blob containers within affected storage accounts (referenced in the overview) to identify which data may have been exposed and assess the potential impact of the exposure.
*   Monitor the `azure.resource.name` field to track which storage accounts are being targeted.
