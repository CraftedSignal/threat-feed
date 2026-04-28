---
title: Unauthorized Guest User Invitations in Azure AD
slug: 2024-01-02-azuread-guest-invite
description: Detection of unauthorized guest user invitations within an Azure Active Directory tenant, indicating potential privilege escalation, persistence, or initial access attempts.
date: "2024-01-02T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - azuread
  - guest-user
  - privilege-escalation
  - persistence
  - initial-access
vendors:
  - Microsoft
products:
  - azure
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-gb/entra/architecture/security-operations-user-accounts#monitoring-external-user-sign-ins
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_ad_guest_users_invited_to_tenant_by_non_approved_inviters.yml
rules:
  - title: Azure AD Guest User Invitation by Non-Approved User
    description: Detects guest users being invited to tenant by non-approved inviters
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078
    data_sources:
      - azure
      - auditlogs
  - title: Azure AD Guest User Invitation - Anomalous Geo-Location
    description: Detects guest users invited from an unusual geographical location
    platform: sigma
    severity: low
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078
    data_sources:
      - azure
      - auditlogs
rules_count: 2
---

This alert focuses on detecting the invitation of guest users to an Azure Active Directory (AD) tenant by accounts that are not pre-approved to perform this action. Unauthorized guest user invitations can be an indicator of various malicious activities. An attacker could be attempting to escalate privileges by adding an account they control, establish persistence by creating a backdoor account, or gain initial access to the environment. This activity might be part of a broader attack aimed at gaining unauthorized access to sensitive resources or data within the organization's Azure environment. It is important to ensure that only authorized personnel can invite external users to maintain security and prevent potential abuse.

## Attack Chain

1. An attacker compromises a low-privilege user account within the Azure AD tenant or uses existing compromised credentials.
2. The attacker attempts to invite an external guest user to the tenant using the compromised account.
3. The Azure AD audit logs record the "Invite external user" operation under the UserManagement category.
4. The audit log event is generated, capturing details such as the user who initiated the invitation (InitiatedBy) and the target guest user's information.
5. The detection logic evaluates if the InitiatedBy user is within the list of approved guest inviters.
6. If the inviting user is not on the approved list, the detection rule triggers, indicating a potentially unauthorized guest invitation.
7. The attacker may then attempt to leverage the newly invited guest account for lateral movement or data exfiltration.
8. The attacker uses the guest account to access resources and data within the Azure AD environment, potentially leading to data breaches or other security incidents.

## Impact

The successful exploitation of this vulnerability can lead to unauthorized access to sensitive data and resources within the Azure AD tenant. While the precise number of potential victims is unknown, the impact could range from a limited breach affecting a small set of resources to a widespread compromise impacting the entire organization. The addition of unauthorized guest accounts can facilitate lateral movement, data exfiltration, and other malicious activities, leading to significant financial and reputational damage.

## Recommendation

*   Implement the provided Sigma rule to detect unauthorized guest user invitations in Azure AD audit logs and tune the `filter` with a list of approved inviters.
*   Review and restrict the number of users authorized to invite guest users to the Azure AD tenant based on business needs.
*   Implement multi-factor authentication (MFA) for all user accounts, including guest accounts, to prevent unauthorized access (related to audit logs).
*   Regularly audit Azure AD logs for any suspicious activity related to user management (related to audit logs).
