---
title: Azure AD FullAccessAsApp Permission Assignment
slug: 2024-01-azuread-fullaccess
description: Detection of 'full_access_as_app' permission assignment to an application in Office 365 Exchange Online, potentially leading to unauthorized access and data exfiltration.
date: "2024-01-29T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - NOBELIUM Group
tags:
  - azure
  - azuread
  - office365
  - persistence
  - nobelium
vendors:
  - Microsoft
products:
  - Office 365 Exchange Online
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/
  - https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/
  - https://attack.mitre.org/techniques/T1098/002/
rules:
  - title: Azure AD FullAccessAsApp Permission Assigned
    description: Detects the assignment of the 'full_access_as_app' permission to an application in Azure AD.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1098.002
      - T1098.003
    data_sources:
      - audit
      - azure
  - title: Azure AD Application Update with Exchange ResourceAppId
    description: Detects updates to applications that reference the Exchange Online ResourceAppId, which may indicate permission abuse.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098.002
    data_sources:
      - audit
      - azure
rules_count: 2
---

This threat brief focuses on the detection of the 'full_access_as_app' permission being assigned to an application within Office 365 Exchange Online. This activity is identified by the GUID 'dc890d15-9560-4a4c-9b7f-a736ec74ec40' and the ResourceAppId '00000002-0000-0ff1-ce00-000000000000'. This permission grants broad control over Office 365 operations, including full access to all mailboxes and the ability to send emails as any user. The observed activity leverages the "Update application" operation in Azure Active Directory AuditLogs. The threat is significant because successful exploitation grants the attacker the ability to impersonate any user within the targeted organization, leading to potential data breaches, financial fraud, or further compromise of the environment. References to Microsoft's response to the Midnight Blizzard campaign indicate that this type of permission abuse has been seen in nation-state attacks.

## Attack Chain

1.  The attacker compromises an Azure AD account with sufficient privileges.
2.  The attacker uses the compromised account to access the Azure portal or uses PowerShell/Graph API.
3.  The attacker registers a malicious application within the Azure AD tenant, or modifies an existing one.
4.  The attacker assigns the 'full_access_as_app' permission (dc890d15-9560-4a4c-9b7f-a736ec74ec40) to the application. This is achieved through the "Update application" operation.
5.  The application gains full access to all mailboxes in the Exchange Online environment (ResourceAppId: 00000002-0000-0ff1-ce00-000000000000).
6.  The attacker leverages the granted permissions to access sensitive emails, contacts, and calendar data from targeted mailboxes.
7.  The attacker may send emails on behalf of other users, potentially leading to phishing attacks or business email compromise (BEC).
8.  The attacker exfiltrates sensitive data or maintains persistence within the environment by creating new rogue applications.

## Impact

Successful assignment of the 'full_access_as_app' permission allows an attacker to access and control all mailboxes within the targeted Office 365 Exchange Online environment. This can lead to significant data breaches, financial losses through BEC attacks, and reputational damage. Organizations in any sector are vulnerable, but those handling sensitive data or operating in regulated industries face the highest risk. Nation-state actors like NOBELIUM have been known to exploit this type of permission abuse to gain long-term access to victim networks.

## Recommendation

*   Deploy the Sigma rule "Azure AD FullAccessAsApp Permission Assigned" to your SIEM and tune for your environment to detect unauthorized assignments of the 'full_access_as_app' permission.
*   Review Azure AD audit logs for "Update application" events where the 'full_access_as_app' permission (dc890d15-9560-4a4c-9b7f-a736ec74ec40) is being assigned.
*   Implement the recommendations from Microsoft's blog post "Midnight Blizzard Guidance for Responders on Nation State Attack" to harden your Azure AD environment and prevent similar attacks.
*   Monitor for applications with excessive permissions, especially those with the 'full_access_as_app' permission, and investigate any anomalies.
*   Regularly audit application permissions in Azure AD to identify and remediate any overly permissive configurations.
