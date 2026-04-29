---
title: Entra ID Excessive Account Lockouts Detected
slug: 2024-01-30-entra-id-lockouts
description: A high volume of failed Microsoft Entra ID sign-in attempts resulting in account lockouts indicates potential brute-force attacks, such as password spraying or credential stuffing, targeting user accounts.
date: "2026-04-22T18:43:05Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - azure
  - entra_id
  - credential_access
  - brute_force
vendors:
  - Microsoft
products:
  - Entra ID
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://www.microsoft.com/en-us/security/blog/2025/05/27/new-russia-affiliated-actor-void-blizzard-targets-critical-sectors-for-espionage/
  - https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-unauthenticated-enum-and-initial-entry/az-password-spraying
  - https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-password-spray
  - https://www.sprocketsecurity.com/blog/exploring-modern-password-spraying
  - https://learn.microsoft.com/en-us/purview/audit-log-detailed-properties
  - https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes
  - https://github.com/0xZDH/Omnispray
  - https://github.com/0xZDH/o365spray
rules:
  - title: Entra ID Excessive Account Lockouts
    description: Detects a high number of failed Entra ID sign-in attempts resulting in account lockouts (error code 50053) from a single source IP.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.003
    data_sources:
      - authentication
      - azure
  - title: Entra ID Username Enumeration
    description: Detects a high number of failed Entra ID sign-in attempts with 'user not found' error (50034) from a single source IP, indicating username enumeration attempts.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595.002
    data_sources:
      - authentication
      - azure
rules_count: 2
---

This alert identifies a surge in failed Microsoft Entra ID sign-in attempts (error code 50053) due to account lockouts, suggesting potential brute-force attacks. Attackers often employ password spraying, credential stuffing, or automated guessing to compromise accounts. This detection uses a threshold-based approach to identify coordinated campaigns targeting multiple users. The Entra ID Smart Lockout feature triggers error code 50053, utilizing IP-based tracking to differentiate between "familiar" and "unfamiliar" locations, with lockouts primarily originating from unfamiliar IPs. Successful exploitation can lead to unauthorized access to sensitive data, lateral movement within the network, and potential data exfiltration.

## Attack Chain

1.  **Initial Access:** The attacker attempts to gain access to Entra ID accounts using compromised or guessed credentials.
2.  **Password Spraying/Credential Stuffing:** The attacker performs password spraying attacks by attempting common passwords across multiple accounts, or credential stuffing attacks by using lists of breached credentials obtained from other sources.
3.  **Authentication Failure:** The sign-in attempts fail due to incorrect credentials, resulting in authentication failure events in Entra ID sign-in logs.
4.  **Smart Lockout Triggered:** Entra ID's Smart Lockout feature detects the repeated failed sign-in attempts from unfamiliar IPs, triggering account lockouts and generating error code 50053.
5.  **Account Lockout:** The target user accounts are locked out, preventing legitimate users from accessing their accounts.
6.  **Potential Enumeration:** Prior to the lockouts, the attacker may perform username enumeration, resulting in error code 50034 (user not found) in the sign-in logs.
7.  **MFA Bypass Attempt (if applicable):** If MFA is not enforced or bypassed, the attacker may attempt to gain access using single-factor authentication.
8.  **Account Compromise (if successful):** If the attacker successfully guesses the password before lockout or bypasses MFA, the account is compromised, allowing unauthorized access to resources.

## Impact

A successful brute-force attack against Entra ID can lead to widespread account compromise. This could result in unauthorized access to sensitive data, business disruption, and potential financial loss. An attacker could leverage compromised accounts to move laterally within the network, escalate privileges, and exfiltrate data. This attack can affect any organization using Microsoft Entra ID for identity and access management.

## Recommendation

*   Deploy the Sigma rule "Entra ID Excessive Account Lockouts Detected" to your SIEM to detect high counts of failed sign-in attempts resulting in account lockouts.
*   Investigate alerts generated by the Sigma rule by pivoting to the raw logs in Discover or Timeline using the provided query and focusing on `event.dataset: "azure.signinlogs" and azure.signinlogs.properties.status.error_code: 50053`.
*   Block suspicious source IPs identified in the investigation using Conditional Access named locations to prevent further brute-force attempts.
*   Implement Conditional Access policies to block legacy authentication protocols like IMAP, SMTP, and POP, which are often targeted in password spraying attacks.
*   Review and enhance Conditional Access policies to ensure comprehensive MFA coverage and prevent MFA bypass attempts.
