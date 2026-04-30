---
title: Azure AD Hybrid Health AD FS Service Deletion for Defense Evasion
slug: 2024-01-03-azuread-adfs-delete
description: Threat actors may delete Azure AD Hybrid Health AD FS service instances after using them to spoof AD FS signing logs for defense evasion.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - attack.defense-impairment
  - attack.t1578.003
  - azure
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify System Image
references:
  - https://o365blog.com/post/hybridhealthagent/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/activity_logs/azure_aadhybridhealth_adfs_service_delete.yml
rules:
  - title: Azure AD Hybrid Health AD FS Service Delete
    description: Detects the deletion of an Azure AD Hybrid Health AD FS service instance in a tenant.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
    techniques:
      - T1578.003
    data_sources:
      - azure
      - activitylogs
  - title: Azure AD Hybrid Health Service Creation followed by Deletion
    description: Detects the creation and subsequent deletion of an Azure AD Hybrid Health service within a short timeframe, which may indicate malicious activity.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
    techniques:
      - T1578.003
    data_sources:
      - azure
      - activitylogs
rules_count: 2
---

An attacker can create a new AD Health ADFS service and a fake server to spoof AD FS signing logs. This involves adding a rogue AD FS service to Azure AD Hybrid Health. Once the attacker no longer requires the spoofed logs, they may delete the service to remove traces of their activity or to hinder investigations. This is achieved via HTTP requests to Azure, specifically targeting the deletion of the AD FS service instance. This activity is logged within Azure Activity Logs, providing an opportunity for detection. Defenders should monitor for unexpected deletions of AD FS service instances within their Azure AD environment.

## Attack Chain

1.  The attacker gains initial access to an Azure tenant with sufficient privileges.
2.  The attacker provisions a new, rogue AD FS service within the Azure AD Hybrid Health Service.
3.  The attacker creates a fake server or modifies an existing one to generate spoofed AD FS signing logs.
4.  The attacker uses the spoofed logs to conduct malicious activity, potentially bypassing security controls.
5.  Once the malicious activity is complete, the attacker initiates the deletion of the rogue AD FS service.
6.  The attacker sends an HTTP request to Azure to delete the service using the `Microsoft.ADHybridHealthService/services/delete` operation.
7.  The Azure Activity Logs record the deletion event with CategoryValue set to 'Administrative' and ResourceProviderValue as 'Microsoft.ADHybridHealthService'.

## Impact

Successful deletion of the AD FS service instance can hinder forensic investigations and potentially mask malicious activity within the Azure AD environment. This can lead to delayed incident response and make it more difficult to identify the source and scope of the attack. The impact depends on the sophistication of the attacker and the extent to which they leveraged the spoofed logs for malicious purposes.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect the deletion of AD FS service instances in Azure AD Hybrid Health (Azure Activity Logs).
*   Investigate any detected instances of `Microsoft.ADHybridHealthService/services/delete` operations where the `ResourceId` contains `AdFederationService` in the Azure Activity Logs.
*   Monitor Azure Activity Logs for unexpected or unauthorized modifications to AD FS service configurations.
