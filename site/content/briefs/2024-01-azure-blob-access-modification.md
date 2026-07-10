---
title: Azure Blob Storage Container Access Level Modified
slug: 2024-01-azure-blob-access-modification
description: The rule identifies modifications to Azure Blob Storage container access levels, which, if unauthorized, may lead to data exposure and exfiltration.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - azure
  - asset-visibility
  - discovery
vendors:
  - Microsoft
products:
  - Azure Blob Storage
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1619
    technique_name: Cloud Storage Object Discovery
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1222
    technique_name: File and Directory Permissions Modification
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
references:
  - https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent
  - https://attack.mitre.org/techniques/T1619/
  - https://attack.mitre.org/techniques/T1222/
  - https://attack.mitre.org/techniques/T1537/
rules:
  - title: Azure Blob Storage Container Access Level Modified
    description: Detects modifications to Azure Blob Storage container access levels.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1619
    data_sources:
      - cloudtrail
      - azure
      - activitylog
  - title: Azure Blob Storage Container Access Level Modified - User
    description: Detects modifications to Azure Blob Storage container access levels by a specific user.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1222
    data_sources:
      - cloudtrail
      - azure
      - activitylog
rules_count: 2
---

This detection rule identifies changes to container access levels in Azure Blob Storage. Anonymous public read access to containers and blobs in Azure is a convenient way to share data, but if access to sensitive data is not carefully managed, it can introduce significant security risks. The rule specifically focuses on detecting modifications to container access settings, aiming to identify potential unauthorized changes that could expose sensitive data. This rule is important for defenders because unauthorized modifications can lead to data breaches, compliance violations, and reputational damage. The rule leverages Azure Activity Logs to monitor for the specific operation related to container access modifications.

## Attack Chain

1.  An attacker gains initial access to an Azure account through compromised credentials or an exposed service principal.
2.  The attacker enumerates existing Azure Blob Storage accounts and containers within the compromised subscription.
3.  The attacker modifies the access level of a specific Blob Storage container to allow public read access using the "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE" operation.
4.  The attacker verifies the successful access level modification by attempting to access the container anonymously.
5.  The attacker exfiltrates sensitive data stored within the now publicly accessible container.
6.  The attacker attempts to cover their tracks by deleting activity logs or creating misleading entries.
7.  The attacker moves laterally to other Azure resources using the compromised credentials or service principal.

## Impact

An unauthorized modification of Azure Blob Storage container access levels can lead to the exposure of sensitive data to the public internet. This can result in data breaches, compliance violations, and reputational damage. The risk score associated with this type of activity is 21, and the severity is classified as low, reflecting the potential impact of unauthorized access and data exposure. The rule aims to detect these modifications early to prevent data exfiltration.

## Recommendation

*   Enable Azure Activity Log monitoring and ensure logs are being ingested into your SIEM or security analytics platform to detect the "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE" operation.
*   Deploy the Sigma rule "Azure Blob Storage Container Access Level Modified" to your SIEM and tune the rule based on your environment to minimize false positives.
*   Review and update access management policies and procedures to prevent unauthorized modifications of container access levels to mitigate T1222.
*   Investigate any detected instances of "MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/WRITE" operations from unfamiliar users or service principals.
