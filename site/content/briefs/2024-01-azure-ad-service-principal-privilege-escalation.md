---
title: Azure AD Service Principal Privilege Escalation
slug: 2024-01-azure-ad-service-principal-privilege-escalation
description: An Azure Active Directory (Azure AD) Service Principal elevates its own privileges by adding itself to a new application role assignment, potentially leading to unauthorized access and control within the Azure environment.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - azure-ad
  - service-principal
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Azure AD
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://splunkbase.splunk.com/app/3110
  - https://splunk.github.io/splunk-add-on-for-microsoft-cloud-services/Install/
  - https://github.com/mvelazc0/BadZure
  - https://www.splunk.com/en_us/blog/security/hunting-m365-invaders-navigating-the-shadows-of-midnight-blizzard.html
  - https://posts.specterops.io/microsoft-breach-what-happened-what-should-azure-admins-do-da2b7e674ebc
rules:
  - title: Azure AD Service Principal Privilege Escalation
    description: Detects when an Azure Service Principal elevates privileges by adding itself to a new app role assignment.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - AuditLogs
      - azure
  - title: Azure AD SPN Role Assignment Modification via Suspicious User Agent
    description: Detects suspicious user agents associated with Azure AD Service Principal role assignment modifications.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - AuditLogs
      - azure
rules_count: 2
---

This detection focuses on the abuse of Azure AD Service Principals (SPNs). SPNs are non-human identities used by applications and services to access Azure resources. An attacker who has compromised an SPN, or is operating with sufficient privileges, may attempt to escalate those privileges by assigning the SPN to a higher-level application role. This allows the SPN to perform actions it was not initially authorized to do, such as reading sensitive data, modifying configurations, or even deploying malicious resources. This technique is particularly concerning as it can be difficult to detect without specific monitoring of Azure AD audit logs. The "BadZure" research project highlights many offensive techniques leveraging Azure AD misconfigurations like this one.

## Attack Chain

1.  The attacker gains initial access to Azure AD, potentially through compromised credentials of an existing user or SPN.
2.  The attacker identifies a target SPN that can be leveraged for privilege escalation.
3.  The attacker uses Azure AD PowerShell or the Azure CLI to add the target SPN to a new, higher-privilege application role assignment. This involves modifying the `AppRoleAssignment` for the SPN.
4.  The `operationName` "Add app role assignment to service principal" is logged in the Azure AD Audit Logs. The `properties.targetResources` field contains information about the modified app role and the target service principal.
5.  The attacker authenticates as the SPN, now possessing the escalated privileges.
6.  The attacker performs actions authorized by the newly acquired role, such as accessing sensitive resources, modifying configurations, or deploying malicious applications.
7.  The attacker attempts to cover their tracks by deleting audit logs or other evidence of their activity (though this may be prevented by appropriate Azure AD logging configurations).

## Impact

Successful privilege escalation via SPN manipulation can grant an attacker complete control over an Azure subscription or specific Azure resources. The impact can range from data breaches and service disruptions to the deployment of ransomware or other malicious payloads within the cloud environment. Given the increasing reliance on cloud services, these attacks have the potential to affect organizations of any size and across any sector. The Microsoft breach and Midnight Blizzard campaign highlighted the importance of these cloud-focused attacks.

## Recommendation

*   Enable the Splunk Add-on for Microsoft Cloud Services to ingest Azure AD Audit Logs via Azure EventHub to monitor for suspicious activity (reference: how_to_implement).
*   Deploy the Sigma rule `Azure AD Service Principal Privilege Escalation` to detect when a service principal adds itself to a new app role assignment (reference: rules).
*   Investigate any instances of SPNs modifying their own `AppRoleAssignment` to identify potential privilege escalation attempts.
*   Implement the `azure_ad_service_principal_privilege_escalation_filter` to reduce false positives by filtering out known good service principals or application roles.
*   Monitor the `user_agent` field in Azure AD Audit Logs for unusual or unexpected user agents associated with SPN activity (reference: search).
