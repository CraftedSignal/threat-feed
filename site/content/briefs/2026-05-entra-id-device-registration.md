---
title: Entra ID Register Device with Unusual User Agent (Azure AD Join)
slug: 2026-05-entra-id-device-registration
description: Detects suspicious Microsoft Entra ID audit events for device registration where details indicate an Azure AD join and the user agent is not a standard registration client, potentially indicating scripted registration, third-party tooling, or malicious device registration for persistence or token abuse.
date: "2026-05-18T10:55:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - entra_id
  - persistence
vendors:
  - Microsoft
products:
  - Entra ID
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://learn.microsoft.com/en-us/entra/identity/devices/concept-directory-join
  - https://github.com/dirkjanm/ROADtools
rules:
  - title: Entra ID Register Device with Unusual User Agent
    description: Detects successful Microsoft Entra ID audit events for Register device where additional details indicate an Azure AD join and the recorded user agent is not one of the common native registration clients.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098.005
    data_sources:
      - audit
      - azure
  - title: Entra ID Device Registration with Non-Standard User Agent - Broad Match
    description: Detects Microsoft Entra ID device registration events with user agents that deviate from common device registration clients (Dsreg, DeviceRegistrationClient, Dalvik).
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1098.005
    data_sources:
      - audit
      - azure
rules_count: 2
---

This detection identifies anomalous device registration activity within Microsoft Entra ID. It focuses on instances where a device is registered with Azure AD using a user agent string that deviates from the typical clients used in standard enrollment processes (Dsreg, DeviceRegistrationClient, or Dalvik-based Android enrollment). The rule is triggered by audit logs showing a successful device registration coupled with an atypical user agent and confirmation of an Azure AD join. This can signify various threats including scripted registration, unauthorized third-party device management tools, or, critically, adversary-driven device registration designed to establish persistence or facilitate token abuse. Defenders should baseline their approved provisioning tools and MDM integrations to reduce false positives.

## Attack Chain

1.  The attacker gains initial access to a user's credentials or a compromised account.
2.  The attacker leverages the compromised credentials to attempt device registration within Entra ID.
3.  The attacker uses a custom or non-standard user-agent string during the device registration process to evade standard detection mechanisms.
4.  The device is registered with Azure AD, creating a new device object within the directory.
5.  The attacker may then use the registered device to obtain Primary Refresh Tokens (PRTs).
6.  The attacker uses the PRTs to authenticate to cloud resources and services, bypassing multi-factor authentication (MFA) if device trust is configured.
7.  The attacker establishes persistence by maintaining access through the registered device, even if the original account credentials are changed.
8.  The attacker performs lateral movement within the cloud environment, accessing sensitive data or performing unauthorized actions.

## Impact

Successful exploitation enables attackers to establish persistent access to cloud resources even after password resets or other security measures are taken. This can lead to data breaches, unauthorized access to sensitive information, and lateral movement within the cloud environment. By registering rogue devices, attackers can bypass MFA controls and maintain long-term access. The impact includes potential financial losses, reputational damage, and disruption of business operations.

## Recommendation

*   Deploy the Sigma rule `Entra ID Register Device with Unusual User Agent` to your SIEM and tune for your environment.
*   Review `azure.auditlogs.properties.userAgent` values in your environment to identify legitimate but uncommon user agents used for device registration. Add exclusions to the Sigma rule as needed.
*   Monitor `azure.auditlogs` for `Register device` events with unusual `azure.auditlogs.properties.additional_details.value` content.
*   Implement Conditional Access policies to restrict device registration to compliant devices and trusted networks.
*   Follow Microsoft's recommendations for tightening device registration and join controls to prevent unauthorized device enrollment.
