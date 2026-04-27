---
title: Entra ID Excessive Account Lockouts Detected
slug: 2024-01-30-entra-id-lockouts
description: A high volume of failed Microsoft Entra ID sign-in attempts resulting in account lockouts indicates potential brute-force attacks, such as password spraying or credential stuffing, targeting user accounts.
date: "2026-04-22T18:43:05Z"
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

This alert identifies a surge in failed Microsoft Entra ID sign-in attempts (error code 50053) due to account lockouts, suggesting potential brute-force attacks. Attackers often employ password spraying, credential stuffing, or automated guessing to compromise accounts. This detection uses a threshold-based approach to identify coordinated campaigns targeting multiple users. The Entra ID Smart Lockout feature triggers error code 50053, utilizing IP-based tracking to differentiate between…
