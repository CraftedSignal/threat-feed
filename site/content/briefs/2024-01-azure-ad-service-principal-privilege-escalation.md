---
title: Azure AD Privileged Role Assigned to Service Principal
slug: 2024-01-azure-ad-service-principal-privilege-escalation
description: Detection of privileged role assignments to service principals in Azure AD, which can lead to unauthorized access and privilege escalation within Azure environments.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - azuread
  - privilege-escalation
  - persistence
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://posts.specterops.io/azure-privilege-escalation-via-service-principal-abuse-210ae2be2a5
  - https://github.com/splunk/security_content/blob/main/detections/cloud/azure_ad_privileged_role_assigned_to_service_principal.yml
rules:
  - title: Azure AD Privileged Role Assigned to Service Principal
    description: Detects the assignment of privileged roles to service principals in Azure AD.
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
      - o365
  - title: Azure AD Service Principal Role Assignment by Unusual User
    description: Detects Azure AD Service Principal role assignments performed by users who do not typically perform such actions.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - cloudtrail
      - azure
      - o365
  - title: Azure AD Privileged Role Assigned to Service Principal - High Volume
    description: Detects a high volume of privileged role assignments to service principals in a short period, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - cloudtrail
      - azure
      - o365
rules_count: 3
---

This brief focuses on the detection of privileged role assignments to service principals within Azure Active Directory (AD). The activity is significant because attackers can exploit service principals with elevated permissions to gain unauthorized access to Azure resources. This can lead to privilege escalation, data compromise, and disruption of critical infrastructure. This activity is detected using Azure AD AuditLogs. Defenders should monitor this behavior to prevent abuse of service principals for malicious purposes. The described activity aligns with tactics observed by multiple threat actors, including NOBELIUM Group and Scattered Lapsus$ Hunters, who are known to target cloud environments for privilege escalation.

## Attack Chain

1.  The attacker gains initial access to an Azure AD tenant, potentially through compromised credentials or other means.
2.  The attacker identifies a service principal within the Azure AD tenant that can be leveraged for privilege escalation.
3.  The attacker uses an account with sufficient privileges to assign a privileged role to the identified service principal.
4.  The "Add member to role" operation is executed, modifying the service principal's roles in Azure AD.
5.  The attacker leverages the service principal with the newly assigned privileged role to access sensitive Azure resources.
6.  The service principal authenticates to Azure services using its assigned credentials or certificates.
7.  The service principal performs actions allowed by the privileged role, such as accessing sensitive data, modifying configurations, or creating new resources.
8.  The attacker maintains persistence by ensuring the service principal retains its privileged role.

## Impact

Successful exploitation allows attackers to gain elevated access to Azure resources, potentially leading to the compromise of sensitive data, disruption of critical infrastructure, and unauthorized modification of Azure configurations. This can result in significant financial losses, reputational damage, and legal liabilities for affected organizations. The number of affected victims and sectors can vary depending on the attacker's objectives and the scope of the compromised Azure environment.

## Recommendation

*   Deploy the provided Sigma rules to your SIEM to detect anomalous role assignments to service principals (see rule: "Azure AD Privileged Role Assigned to Service Principal").
*   Review and audit existing role assignments for service principals in Azure AD to identify and remediate any unnecessary or excessive privileges.
*   Implement multi-factor authentication (MFA) for all user accounts, including those used to manage Azure AD, to prevent unauthorized access and privilege escalation.
*   Monitor Azure AD AuditLogs for suspicious activity related to service principal management and role assignments (data_source: Azure Active Directory Add member to role).
*   Investigate any alerts generated by the Sigma rule and determine whether the role assignment was legitimate or malicious.
*   Filter as needed based on known legitimate administrative tasks (see: known_false_positives).
