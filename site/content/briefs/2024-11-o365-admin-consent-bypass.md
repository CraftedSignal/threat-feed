---
title: O365 Admin Consent Bypassed by Service Principal
slug: 2024-11-o365-admin-consent-bypass
description: A service principal in Office 365 Azure Active Directory assigns app roles without standard admin consent, potentially bypassing critical administrative controls and leading to unauthorized access or privilege escalation.
date: "2024-11-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azuread
  - office365
  - serviceprincipal
  - adminconsent
  - persistence
vendors:
  - Microsoft
products:
  - Office 365
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
  - https://attack.mitre.org/techniques/T1098/003/
  - https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/
  - https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/
  - https://attack.mitre.org/techniques/T1098/002/
  - https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/
  - https://winsmarts.com/how-to-grant-admin-consent-to-an-api-programmatically-e32f4a100e9d
rules:
  - title: O365 Admin Consent Bypassed by Service Principal
    description: Detects instances where a service principal in Office 365 Azure Active Directory assigns app roles without standard admin consent, potentially bypassing critical administrative controls.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1098.003
    data_sources:
      - webserver
      - azure
  - title: O365 Suspicious Role Assignment by Service Principal
    description: Detects a service principal assigning high-privilege roles.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - webserver
      - azure
rules_count: 2
---

This detection identifies instances where a service principal within an Office 365 Azure Active Directory environment assigns application roles without undergoing the standard administrative consent process. This activity is identified through the analysis of `o365_management_activity` logs, specifically focusing on events related to the 'Add app role assignment to service principal' operation. This bypass can lead to significant security breaches as it circumvents critical administrative controls and allows for unauthorized privilege escalation. The activity was observed in January 2024. Successful exploitation could enable attackers to assign sensitive permissions through automated processes, leading to a compromise of the environment's overall security posture.

## Attack Chain

1.  An attacker compromises a service principal within the Azure Active Directory environment, potentially through credential stuffing or other means of initial access.
2.  The attacker leverages the compromised service principal to initiate the "Add app role assignment to service principal" operation, bypassing normal admin consent workflows.
3.  The attacker assigns elevated privileges or roles, such as Global Administrator or Application Administrator, to a target user or service principal.
4.  The target user or service principal, now possessing elevated privileges, can access sensitive data, modify configurations, or create new accounts.
5.  The attacker uses the elevated privileges to establish persistence within the environment, such as creating backdoor accounts or modifying authentication policies.
6.  The attacker moves laterally to other systems or applications within the organization, leveraging the compromised Azure AD environment as a pivot point.
7.  The attacker exfiltrates sensitive data, disrupts critical services, or deploys ransomware, depending on their objectives.

## Impact

Successful exploitation of this bypass can lead to unauthorized access to sensitive data, modification of critical configurations, and the creation of persistent backdoors within the Office 365 environment. The Microsoft Security Response Center has published guidance related to this technique in January 2024 in response to activity by the nation-state actor Midnight Blizzard. This type of attack can affect organizations of any size that rely on Office 365 services, potentially leading to significant financial losses, reputational damage, and legal liabilities.

## Recommendation

*   Deploy the Sigma rule `O365 Admin Consent Bypassed by Service Principal` to your SIEM to detect this activity.
*   Review service principal configurations within Azure AD and ensure that appropriate consent policies are in place to prevent unauthorized role assignments.
*   Monitor `o365_management_activity` logs for events related to "Add app role assignment to service principal" and investigate any anomalies.
*   Implement multi-factor authentication (MFA) for all user accounts, including service principals, to reduce the risk of compromise.
*   Enforce the principle of least privilege when assigning roles and permissions to service principals.
*   Regularly audit Azure AD logs for suspicious activity patterns that may indicate a compromised service principal.
