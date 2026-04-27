---
title: Entra ID ADRS Token Request by Microsoft Authentication Broker
slug: 2026-06-adrs-token-request
description: Detects suspicious OAuth 2.0 token requests where the Microsoft Authentication Broker requests access to the Device Registration Service on behalf of a user principal, potentially indicating an attempt to abuse device registration for unauthorized persistence.
date: "2026-04-10T17:57:29Z"
severities:
  - medium
tags:
  - azure
  - entra_id
  - persistence
  - oauth
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
  - https://attack.mitre.org/techniques/T1098/
  - https://attack.mitre.org/techniques/T1098/005/
  - https://attack.mitre.org/techniques/T1550/
  - https://attack.mitre.org/tactics/TA0003/
  - https://attack.mitre.org/tactics/TA0005/
ioc_counts:
  domain: 1
rules:
  - title: Entra ID ADRS Token Request by Microsoft Authentication Broker
    description: Detects suspicious OAuth 2.0 token requests where the Microsoft Authentication Broker requests access to the Device Registration Service (ADRS) on behalf of a user principal.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098.005
    data_sources:
      - webserver
      - azure
  - title: Entra ID ADRS Token Request - Interactive User
    description: Detects suspicious OAuth 2.0 token requests for interactive users
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1098.005
    data_sources:
      - webserver
      - azure
rules_count: 2
---

This detection identifies potentially malicious activity within Microsoft Entra ID (Azure AD) involving the Microsoft Authentication Broker (MAB). Specifically, it focuses on OAuth 2.0 token requests where MAB (application ID 29d9ed98-a469-4536-ade2-f981bc1d605e) requests access to the Device Registration Service (DRS) (resource ID 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9) on behalf of a user. The presence of the `adrs_access` scope within the authentication processing details signals an attempt to…
