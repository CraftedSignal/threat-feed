---
title: Azure AD Multi-Factor Authentication Disabled
slug: 2024-01-azuread-mfa-disable
description: Detection of attempts to disable multi-factor authentication (MFA) for an Azure AD user by identifying the 'Disable Strong Authentication' operation in Azure Active Directory AuditLogs, which allows adversaries to maintain persistence.
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - mfa
  - persistence
  - credential-access
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Impair Defenses
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1586
    technique_name: Compromise Help Desk
references:
  - https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks
  - https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userstates
  - https://attack.mitre.org/tactics/TA0005/
  - https://attack.mitre.org/techniques/T1556/
rules:
  - title: Azure AD MFA Disabled via AuditLogs
    description: Detects the disabling of multi-factor authentication (MFA) for a user in Azure Active Directory by identifying the 'Disable Strong Authentication' operation in AuditLogs.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1556.006
    data_sources:
      - webserver
      - linux
  - title: Azure AD MFA Disable Strong Authentication User Agent
    description: Detects potentially malicious user agent strings associated with MFA disabling activity.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1556.006
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This analytic identifies instances where multi-factor authentication (MFA) is disabled for a user in Azure Active Directory (Azure AD). The detection is based on Azure AD AuditLogs, specifically looking for the "Disable Strong Authentication" operation. This activity is a critical indicator of potential malicious activity, as disabling MFA can enable attackers to maintain persistence within the environment using compromised accounts. This action circumvents a key security control, allowing for unauthorized access and a potentially prolonged, undetected presence within the compromised environment. The scope of this threat includes any organization leveraging Azure AD for identity and access management.

## Attack Chain

1.  An attacker gains initial access to a valid user's credentials through methods such as phishing, credential stuffing, or purchasing them on the dark web.
2.  The attacker authenticates to Azure AD using the compromised credentials.
3.  The attacker attempts to disable MFA for the compromised user account. This action generates an AuditLog event with the operation name "Disable Strong Authentication."
4.  The attacker, if successful in disabling MFA, logs out and re-authenticates to establish a session without MFA.
5.  The attacker leverages the compromised account to access sensitive resources and data within the Azure environment.
6.  The attacker establishes persistence by creating backdoors or modifying existing configurations to maintain access even if the initial vulnerability is patched.
7.  The attacker performs lateral movement to gain access to additional user accounts and resources within the organization.

## Impact

A successful attack resulting in disabled MFA can lead to significant data breaches, financial losses, and reputational damage. Organizations relying on Azure AD for authentication are particularly vulnerable. The impact includes unauthorized access to sensitive data, potential data exfiltration, and the establishment of long-term persistence within the environment. Without MFA, compromised accounts can be freely accessed, enabling attackers to move laterally and escalate privileges.

## Recommendation

*   Deploy the Sigma rule provided in this brief to your SIEM to detect instances of MFA being disabled in Azure AD logs.
*   Investigate any detected instances of "Disable Strong Authentication" in Azure AD AuditLogs, focusing on the `user`, `initiatedBy`, and `user_agent` fields to determine if the activity is legitimate or suspicious.
*   Enable alerting on the Sigma rule to provide real-time notification of potential MFA disabling events.
*   Implement stricter access controls and monitoring for privileged accounts that have the ability to disable MFA for other users.
*   Review user training programs to emphasize the importance of MFA and the risks associated with compromised credentials, referencing the MFA documentation (https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks).
*   Implement Conditional Access policies in Azure AD to enforce MFA based on various factors, such as location, device, and application, as outlined in (https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userstates).
