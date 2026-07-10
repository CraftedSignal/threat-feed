---
title: Entra ID External Authentication Methods (EAM) Modified
slug: 2024-01-entra-id-eam-modification
description: Modification of Entra ID external authentication methods (EAM) via the Microsoft Graph API can allow attackers to bypass multi-factor authentication (MFA) and establish persistence or gain unauthorized access via bring-your-own IdP (BYOIDP) methods.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - entra-id
  - persistence
  - authentication
vendors:
  - Microsoft
products:
  - Entra ID
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://dirkjanm.io/persisting-with-federated-credentials-entra-apps-managed-identities/
rules:
  - title: Entra ID External Authentication Methods (EAM) Modified
    description: Detects modifications to external authentication methods (EAMs) in Microsoft Entra ID via the Microsoft Graph API, indicating potential MFA bypass and persistence attempts.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1556.009
    data_sources:
      - webserver
      - linux
  - title: Entra ID Graph API Request with AuthenticationMethod.ReadWrite.All Scope
    description: Detects Graph API requests using the AuthenticationMethod.ReadWrite.All scope, which is required to manage authentication methods.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1556.009
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Attackers are increasingly targeting cloud identity providers to establish persistence and bypass security controls. This rule detects modifications to external authentication methods (EAMs) within Microsoft Entra ID, leveraging the Microsoft Graph API. The activity is focused on manipulating authentication policies to allow attackers to bypass multi-factor authentication (MFA) requirements. Successful modification of EAMs can enable adversaries to use bring-your-own identity provider (BYOIDP) methods, granting them unauthorized access to user accounts and sensitive resources. The targeted scope is Entra ID environments, and the activity involves the use of PATCH requests to the `/authenticationMethodsPolicy` endpoint.

## Attack Chain

1.  An attacker compromises an account with sufficient privileges to modify Entra ID authentication settings.
2.  The attacker authenticates to Azure using the compromised account's credentials.
3.  The attacker crafts a PATCH request to the Microsoft Graph API endpoint `/authenticationMethodsPolicy`.
4.  The PATCH request modifies the configuration of external authentication methods (EAMs) within Entra ID.
5.  The attacker leverages privileged scopes such as `AuthenticationMethod.ReadWrite.All` for the request.
6.  The attacker successfully bypasses MFA for targeted user accounts using the modified EAM settings.
7.  The attacker gains unauthorized access to sensitive resources within the Entra ID environment.
8.  The attacker maintains persistence by continually using the modified authentication methods.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data and systems within the Entra ID environment. Attackers can establish persistent access, even if the original compromised account is remediated. The impact spans across any applications and resources relying on Entra ID for authentication. Depending on the compromised account's permissions, the attacker could potentially escalate privileges and gain control over the entire Entra ID tenant.

## Recommendation

*   Deploy the Sigma rule "Entra ID External Authentication Methods (EAM) Modified" to detect modifications to authentication policies (rule.query).
*   Investigate any detected activity where `http.request.method` is "PATCH" and `url.path` contains `authenticationMethodsPolicy` (rule.query).
*   Review and restrict the assignment of the `AuthenticationMethod.ReadWrite.All` scope to service principals to limit the potential for abuse (references).
*   Monitor Azure Graph Activity logs for unusual activity related to EAM settings and correlate with other identity-related events (rule.index).
*   Implement stricter RBAC or conditional access policies to prevent unauthorized EAM changes in the future (references).
