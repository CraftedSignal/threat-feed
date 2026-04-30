---
title: Okta Identity Provider Creation Detected
slug: 2024-01-okta-idp-created
description: An adversary may create a rogue identity provider within Okta to establish persistence and potentially escalate privileges by impersonating legitimate users or bypassing multi-factor authentication.
date: "2024-01-25T12:00:00Z"
type: advisory
types:
  - advisory
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

The creation of a new identity provider (IdP) in Okta is a sensitive action that should be closely monitored. While legitimate administrators may create IdPs for federation purposes, adversaries can abuse this functionality to establish persistence or escalate privileges within an Okta environment. This involves creating a malicious IdP that they control and configuring it to authenticate users, potentially bypassing existing security controls such as multi-factor authentication (MFA) or implementing cross-tenant impersonation. The creation of a rogue IdP within Okta can be an indicator of compromise, potentially leading to unauthorized access to applications and data protected by Okta. Defenders should monitor Okta system logs for the creation of new identity providers and validate their legitimacy.

## Attack Chain

1.  An attacker gains initial access to an Okta tenant with sufficient administrative privileges, either through compromised credentials or by exploiting a vulnerability.
2.  The attacker navigates to the Okta admin console.
3.  The attacker creates a new identity provider (IdP) within the Okta tenant (system.idp.lifecycle.create).
4.  The attacker configures the rogue IdP with attacker-controlled settings, such as SAML endpoints or OIDC configurations, potentially pointing to an attacker-controlled server.
5.  The attacker configures routing rules within Okta to direct specific users or groups to authenticate through the newly created, malicious IdP.
6.  Users attempting to access Okta-protected applications are redirected to the attacker-controlled IdP for authentication.
7.  The attacker's IdP captures user credentials or issues fraudulent authentication tokens, allowing the attacker to impersonate legitimate users.
8.  The attacker leverages the stolen credentials or fraudulent tokens to access sensitive applications and data protected by Okta, achieving their objective of data theft or service disruption.

## Impact

A successful attack involving the creation of a rogue Okta identity provider can lead to significant consequences. Attackers can gain persistent access to the Okta environment, bypass multi-factor authentication, and impersonate legitimate users. This can result in unauthorized access to sensitive applications and data, data breaches, financial loss, and reputational damage. The scope of the impact depends on the privileges of the compromised accounts and the sensitivity of the data accessed.

## Recommendation

*   Deploy the Sigma rule "Okta Identity Provider Created" to your SIEM to detect the creation of new identity providers and tune it for your environment.
*   Regularly review and validate all configured identity providers within your Okta tenant to ensure their legitimacy.
*   Implement strong access controls and multi-factor authentication for all Okta administrative accounts to prevent unauthorized creation of identity providers.
*   Monitor Okta system logs for suspicious activity related to identity provider configuration and authentication.
*   Investigate any alerts triggered by the "Okta Identity Provider Created" Sigma rule to determine the legitimacy of the IdP creation event.
