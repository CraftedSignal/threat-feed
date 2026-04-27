---
title: Device Code Phishing Campaign Targeting Cloud Platforms
slug: 2026-03-device-code-phishing
description: A phishing campaign abuses Microsoft's Device Code OAuth flow to gain access to cloud-based file storage and document workflow platforms, bypassing traditional credential harvesting.
date: "2026-03-25T12:00:00Z"
severities:
  - high
tags:
  - credential-access
  - initial-access
  - phishing
  - oauth
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://www.reddit.com/r/blueteamsec/comments/1s26zoe/active_device_code_phishing_campaign/
  - https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel/blob/main/2026-03-23-%20Device-Code-based-OAuth-Phishing.txt
rules:
  - title: Detect Suspicious Device Code Authentication
    description: Detects unusual device code authentication activity in Azure AD logs, potentially indicating OAuth phishing attempts.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1189
    data_sources:
      - authentication
      - azure_ad
  - title: Detect New OAuth Application Consent
    description: Detects when a user grants consent to a new OAuth application, which can be indicative of a device code phishing attack.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1189
    data_sources:
      - authentication
      - azure_ad
rules_count: 2
---

An active phishing campaign is leveraging Microsoft's Device Code OAuth flow to target users of cloud-based file storage and document workflow platforms. Unlike traditional phishing attacks that aim to steal usernames and passwords directly, this campaign exploits a legitimate authentication mechanism to gain unauthorized access. The campaign impersonates popular cloud services, enticing users to enter a provided device code on a Microsoft login page. By doing so, victims inadvertently grant…
