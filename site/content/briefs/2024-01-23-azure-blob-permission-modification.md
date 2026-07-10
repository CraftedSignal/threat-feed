---
title: Azure Blob Storage Permissions Modified for Defense Evasion
slug: 2024-01-23-azure-blob-permission-modification
description: An adversary may modify Azure Blob Storage permissions to weaken security controls, leading to potential data exposure or loss; this rule detects such modifications by monitoring Azure activity logs for specific operations related to permission changes on blobs.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - cloud
  - defense_evasion
vendors:
  - Microsoft
products:
  - Azure Blob Storage
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1222
    technique_name: File and Directory Permissions Modification
references:
  - https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles
  - https://attack.mitre.org/techniques/T1222/
  - https://attack.mitre.org/tactics/TA0005/
rules:
  - title: Azure Blob Storage Permissions Modified
    description: Detects when Azure role-based access control (Azure RBAC) permissions are modified for an Azure Blob, which may indicate defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1222
    data_sources:
      - cloudtrail
      - azure
  - title: Azure Blob Container Permissions Modified
    description: Detects modifications to Azure Blob container permissions, potentially indicating malicious activity or misconfiguration.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1222
    data_sources:
      - cloudtrail
      - azure
rules_count: 2
---

This detection rule identifies when Azure role-based access control (Azure RBAC) permissions are modified for an Azure Blob. An adversary may intentionally alter permissions to weaken a target's security posture, facilitating unauthorized access or data exfiltration. Alternatively, an administrator might inadvertently make such modifications, creating vulnerabilities that could lead to data exposure or loss. This rule focuses on monitoring Azure activity logs for specific operations related to permission changes on blobs. The rule is designed to detect successful permission changes and alerts analysts to potential security breaches or misconfigurations. The rule is compatible with data from the Azure Fleet integration, Filebeat module, or similarly structured data.

## Attack Chain

1.  An attacker gains initial access to an Azure account, possibly through compromised credentials or exploiting a vulnerability.
2.  The attacker enumerates existing Azure Blob Storage containers and their associated permissions to identify potential targets for privilege escalation or data access.
3.  The attacker attempts to modify the permissions of a specific blob within a storage container using operations like `MICROSOFT.STORAGE/STORAGEACCOUNTS/BLOBSERVICES/CONTAINERS/BLOBS/MODIFYPERMISSIONS/ACTION`.
4.  The Azure RBAC system processes the permission modification request, validating the attacker's credentials and authorization.
5.  If the attacker possesses sufficient privileges or exploits a misconfiguration, the permission modification is successfully applied to the target blob.
6.  The attacker leverages the modified permissions to gain unauthorized access to the blob's content, potentially containing sensitive data.
7.  The attacker exfiltrates the data or uses the altered access to further compromise other resources within the Azure environment.

## Impact

Successful modification of Azure Blob Storage permissions can lead to unauthorized data access, data breaches, and potential compromise of sensitive information stored within the blobs. This can impact confidentiality, integrity, and availability of critical business data. The risk score is 47, indicating a significant potential impact.

## Recommendation

*   Deploy the Sigma rule `Azure Blob Storage Permissions Modified` to your SIEM to detect unauthorized permission changes in Azure Blob Storage.
*   Review Azure activity logs to identify the user or service principal associated with the permission modification event, as described in the rule's description.
*   Implement stricter Azure RBAC policies to ensure that only necessary permissions are granted, mitigating the risk of unauthorized modifications.
*   Create exceptions for specific user accounts or roles that frequently perform legitimate permission modifications, as described in the `false_positives` section of the rule.
