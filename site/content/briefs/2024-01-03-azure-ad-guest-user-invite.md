---
title: Azure AD External Guest User Invitation
slug: 2024-01-03-azure-ad-guest-user-invite
description: Detection of an external guest user invitation in Azure AD through monitoring Azure AD AuditLogs, which, if malicious, can lead to unauthorized access, data breaches, or further exploitation by abusing external identities.
date: "2024-01-03T10:00:00Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - azuread
  - cloud
  - persistence
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
references:
  - https://dirkjanm.io/assets/raw/US-22-Mollema-Backdooring-and-hijacking-Azure-AD-accounts_final.pdf
  - https://www.blackhat.com/us-22/briefings/schedule/#backdooring-and-hijacking-azure-ad-accounts-by-abusing-external-identities-26999
  - https://attack.mitre.org/techniques/T1136/003/
  - https://docs.microsoft.com/en-us/azure/active-directory/external-identities/b2b-quickstart-add-guest-users-portal
rules:
  - title: Azure AD External Guest User Invited
    description: Detects the invitation of an external guest user within Azure AD
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1136.003
    data_sources:
      - cloudtrail
      - azure
      - o365
  - title: Azure AD Guest User Invited by Suspicious User Agent
    description: Detects the invitation of an external guest user within Azure AD by a suspicious User Agent
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1136.003
    data_sources:
      - cloudtrail
      - azure
      - o365
rules_count: 2
---

This analytic detects the invitation of external guest users within Azure Active Directory (Azure AD). The detection focuses on identifying specific events recorded in the Azure AD AuditLogs, triggered when a new external user is invited to the tenant. While legitimate use cases exist for inviting guest users, malicious actors can abuse this feature to gain unauthorized access to internal resources, establish persistence, and potentially compromise sensitive data. The activity is detected using the "Invite external user" operation name within the Azure AD AuditLogs. This analytic helps defenders identify potentially malicious invitations that could lead to broader security incidents.

## Attack Chain

1. An attacker gains initial access to an Azure AD account with sufficient privileges to invite external users.
2. The attacker navigates to the Azure AD portal or uses PowerShell/Azure CLI to manage users.
3. The attacker initiates the "Invite external user" process, providing an external email address.
4. Azure AD generates an invitation to the specified external user.
5. The external user receives the invitation and accepts it, creating a guest user account in the Azure AD tenant.
6. The attacker assigns the newly created guest user account permissions to access specific resources within the Azure AD environment, such as applications or data.
7. The attacker uses the guest user account to access these resources, potentially exfiltrating data or performing other malicious activities.
8. The attacker maintains persistence by ensuring the guest user account remains active and retains its permissions over time.

## Impact

A successful attack leveraging malicious guest user invitations can lead to unauthorized access to sensitive data and applications. This could result in data breaches, intellectual property theft, or financial losses. The impact can vary depending on the permissions granted to the guest user account and the resources they are able to access. The references suggest this is a real threat that has been used in attacks.

## Recommendation

*   Deploy the Sigma rule `Azure AD External Guest User Invited` to your SIEM and tune for your environment to detect potentially malicious external user invitations.
*   Review Azure AD audit logs for suspicious "Invite external user" events, paying close attention to the `initiatedBy` and `user` fields, to uncover unauthorized invitations.
*   Implement multi-factor authentication (MFA) for all Azure AD accounts, including administrators, to reduce the risk of account compromise.
*   Regularly review and audit the permissions assigned to guest user accounts to ensure they adhere to the principle of least privilege.
*   Monitor the references provided in this brief to stay up to date with the latest tactics and techniques used by attackers abusing external identities in Azure AD.
