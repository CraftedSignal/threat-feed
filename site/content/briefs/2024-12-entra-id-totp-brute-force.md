---
title: Azure Entra ID MFA TOTP Brute Force Attempted
slug: 2024-12-entra-id-totp-brute-force
description: Identifies brute force attempts against Azure Entra multi-factor authentication (MFA) Time-based One-Time Password (TOTP) verification codes, characterized by high-frequency failed attempts for a single user across numerous distinct sessions, potentially indicating programmatic attempts to bypass MFA.
date: "2024-12-11T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - entra_id
  - mfa
  - totp
  - brute_force
  - credential_access
vendors:
  - Microsoft
products:
  - Azure Entra ID
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://www.oasis.security/resources/blog/oasis-security-research-team-discovers-microsoft-azure-mfa-bypass
  - https://learn.microsoft.com/en-us/entra/identity/
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-ins
rules:
  - title: Entra ID MFA TOTP Brute Force Attempted (Process)
    description: Detects brute force attempts against Azure Entra MFA TOTP codes based on process activity
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - process_creation
      - windows
  - title: Entra ID MFA TOTP Brute Force - High Failure Count
    description: Detects potential Entra ID MFA TOTP brute force attempts based on a high count of failed authentications with OATH verification codes
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - network_connection
      - windows
  - title: Entra ID MFA TOTP Brute Force - Error Code 500121
    description: Detects potential Entra ID MFA TOTP brute force attempts based on the error code 500121
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

This detection rule identifies potential brute-force attacks targeting Azure Entra ID multi-factor authentication (MFA) that leverages Time-based One-Time Passwords (TOTP). The rule focuses on detecting a high volume of failed TOTP authentication attempts associated with a single user account within a short timeframe and across a high number of distinct session IDs. This behavior suggests an attacker is programmatically attempting to guess the correct TOTP code by rapidly generating multiple sessions, potentially bypassing MFA. The rule requires Entra ID sign-in logs via the Azure integration to be enabled and streaming to an Event Hub. The original rule was created on 2024/12/11 and updated on 2026/04/10.

## Attack Chain

1. The attacker gains initial access to a valid username, likely through credential harvesting or password spraying.
2. The attacker attempts to sign in to an Azure Entra ID resource (e.g., MyApps, Microsoft Graph).
3. Azure Entra ID prompts the user for MFA, specifically a TOTP verification code.
4. The attacker programmatically generates multiple sign-in sessions with different session IDs.
5. For each session, the attacker rapidly submits numerous incorrect TOTP codes in an attempt to guess the correct code.
6. Each failed TOTP attempt generates a sign-in log entry with a "FAILURE" result signature or error code 500121, and auth_method "OATH verification code".
7. If a correct TOTP code is guessed, the attacker successfully authenticates and gains access to the targeted resource.
8. The attacker leverages the compromised account to perform malicious activities such as data exfiltration or lateral movement.

## Impact

A successful brute-force attack against Azure Entra ID MFA could allow an attacker to bypass security controls and gain unauthorized access to sensitive resources. This can lead to data breaches, financial loss, and reputational damage. The impact depends on the permissions and access levels associated with the compromised user account. The targeted resources may include applications, services, and data stored within the Azure Entra ID environment.

## Recommendation

*   Enable Entra ID sign-in logs via the Azure integration to ensure the availability of necessary log data, as specified in the rule setup instructions.
*   Deploy the provided Sigma rule to your SIEM to detect potential TOTP brute force attempts and tune the thresholds (event count >= 20 and session ID count distinct >= 10) according to your environment.
*   Investigate and validate the source IP address of failed TOTP attempts against known good locations and block suspicious IPs.
*   Review conditional access policies applied to users and groups in Entra ID to ensure proper configurations and restrict anomalous login behavior.
*   Monitor authentication failures across the environment to identify potential brute-force attempts targeting other accounts.
