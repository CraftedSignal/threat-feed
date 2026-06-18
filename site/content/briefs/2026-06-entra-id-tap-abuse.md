---
title: Microsoft Entra ID Temporary Access Pass (TAP) Abuse for MFA Bypass and Persistence
slug: 2026-06-entra-id-tap-abuse
description: An attacker with elevated privileges abuses the Microsoft Entra ID Temporary Access Pass (TAP) feature to bypass multi-factor authentication (MFA), gain unauthorized access to target user accounts, and establish persistence by registering new authentication methods.
date: "2026-06-18T15:39:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - identity
  - azure
  - entra-id
  - mfa-bypass
  - persistence
  - lateral-movement
  - initial-access
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass
  - https://dirkjanm.io/lateral-movement-and-hash-dumping-with-temporary-access-passes-microsoft-entra/
  - https://specterops.io/blog/2023/03/29/id-tap-that-pass/
rules:
  - title: Detect Microsoft Entra ID Temporary Access Pass Creation
    description: Detects the creation of a Temporary Access Pass (TAP) for an Entra ID user account, a high-privilege action that bypasses MFA and can be used for initial access or persistence.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1078.004
      - T1550
    data_sources:
      - auditlogs
      - azure
  - title: Detect Microsoft Entra ID Sign-in Using Temporary Access Pass
    description: Identifies successful sign-ins to Microsoft Entra ID using a Temporary Access Pass (TAP), which bypasses MFA and indicates potential attacker activity following TAP creation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078.004
      - T1550
    data_sources:
      - signinlogs
      - azure
  - title: Detect New Authentication Method Registration in Entra ID
    description: Detects when a user registers a new authentication method (e.g., FIDO2, phone, app) in Microsoft Entra ID. This can indicate an attacker establishing persistence after compromising an account, especially following a Temporary Access Pass (TAP) usage.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098
      - T1550
    data_sources:
      - auditlogs
      - azure
rules_count: 3
---

This threat details the abuse of the Temporary Access Pass (TAP) feature within Microsoft Entra ID by malicious actors. An attacker who has gained User Administrator or Authentication Administrator privileges can exploit these roles to create a TAP for any target Entra ID user account. TAPs are a powerful credential, as they are time-limited, allow for passwordless authentication, and crucially, bypass all existing Multi-Factor Authentication (MFA) requirements, including phishing-resistant methods. Threat actors leverage this capability to sign into compromised accounts without needing the original password, and critically, register new, persistent authentication methods (such as FIDO2 security keys or Microsoft Authenticator app registrations) before the TAP expires. This establishes a durable backdoor, enabling continued unauthorized access, lateral movement, and potential data exfiltration, even if the initial compromise vector is remediated and the TAP itself expires.

## Attack Chain

1.  Attacker gains User Administrator or Authentication Administrator privileges within Microsoft Entra ID through an undisclosed initial access vector.
2.  Leveraging these elevated administrative privileges, the attacker creates a Temporary Access Pass (TAP) for a target Entra ID user account, which is recorded in `azure.auditlogs`.
3.  The generated TAP acts as a time-limited, single-use passcode that bypasses all existing MFA policies and requirements for the target account.
4.  The attacker uses the newly issued TAP to successfully sign into the target user account, as evidenced by entries in `azure.signinlogs` with "Temporary Access Pass" as the authentication method.
5.  During the active session authenticated by the TAP, the attacker registers one or more new, persistent authentication methods (e.g., FIDO2 security key, Microsoft Authenticator app) for the compromised account.
6.  Upon expiration or revocation of the TAP, the attacker retains persistent access to the target account via the newly registered authentication methods, bypassing the original password and MFA setup.
7.  With persistent access, the attacker can proceed with objectives such as data exfiltration, lateral movement within the cloud environment, or further privilege escalation.

## Impact

The successful exploitation of the Entra ID TAP feature can lead to complete account compromise, effectively bypassing all MFA protections in place, including phishing-resistant methods. Attackers can establish long-term persistence within an organization's cloud environment by registering new authentication methods, rendering password changes or MFA resets ineffective without careful post-incident remediation. This can result in unauthorized access to sensitive data, financial systems, or critical infrastructure, and enable further lateral movement within the compromised cloud tenancy. While specific victim numbers are not provided, organizations heavily reliant on Microsoft Entra ID for identity management are at risk, particularly those with insufficiently protected administrative accounts.

## Recommendation

*   Deploy the Sigma rules provided in this brief to your SIEM, specifically the rules detecting 'Microsoft Entra ID Temporary Access Pass Creation', 'Microsoft Entra ID Sign-in Using Temporary Access Pass', and 'New Authentication Method Registration in Entra ID'.
*   Enable comprehensive logging for `azure.auditlogs` and `azure.signinlogs` within Microsoft Entra ID to ensure telemetry is available for the detection rules.
*   Regularly audit the assignments for 'User Administrator' and 'Authentication Administrator' roles in Microsoft Entra ID, ensuring least privilege and strong protections for these accounts.
*   Implement strict change management processes for all identity-related administrative actions to identify unauthorized TAP creations in `azure.auditlogs`.
