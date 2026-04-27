---
title: Okta Identity Provider Creation Detected
slug: 2024-01-okta-idp-created
description: An adversary may create a rogue identity provider within Okta to establish persistence and potentially escalate privileges by impersonating legitimate users or bypassing multi-factor authentication.
date: "2024-01-25T12:00:00Z"
severities:
  - medium
tags:
  - identityprovider
  - okta
  - persistence
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection
rules:
  - title: Okta Identity Provider Created
    description: Detects when a new identity provider is created for Okta.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1098.001
    data_sources:
      - okta
      - okta
  - title: Okta Identity Provider Update
    description: Detects when an existing identity provider is updated in Okta, which could indicate malicious configuration changes.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1098.001
    data_sources:
      - okta
      - okta
  - title: Okta Routing Rule Created for Identity Provider
    description: Detects when a new routing rule is created for an identity provider, which may indicate an attempt to redirect users to a malicious IdP.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1098.001
    data_sources:
      - okta
      - okta
rules_count: 3
---

The creation of a new identity provider (IdP) in Okta is a sensitive action that should be closely monitored. While legitimate administrators may create IdPs for federation purposes, adversaries can abuse this functionality to establish persistence or escalate privileges within an Okta environment. This involves creating a malicious IdP that they control and configuring it to authenticate users, potentially bypassing existing security controls such as multi-factor authentication (MFA) or…
