---
title: Azure AD User ImmutableId Attribute Modification for Persistence
slug: 2026-05-azure-ad-immutableid-update
description: The following analytic identifies modifications to the SourceAnchor (ImmutableId) attribute for an Azure Active Directory user, which is a step in setting up an Azure AD identity federation backdoor that allows an attacker to impersonate any user and bypass MFA.
date: "2026-05-28T17:47:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azuread
  - persistence
  - identityfederation
  - backdoor
  - cloud
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://docs.microsoft.com/en-us/azure/active-directory/hybrid/plan-connect-design-concepts
  - https://www.mandiant.com/resources/remediation-and-hardening-strategies-microsoft-365-defend-against-apt29-v13
  - https://o365blog.com/post/federation-vulnerability/
  - https://www.inversecos.com/2021/11/how-to-detect-azure-active-directory.html
  - https://www.mandiant.com/resources/blog/detecting-microsoft-365-azure-active-directory-backdoors
  - https://attack.mitre.org/techniques/T1098/
rules:
  - title: Detect Azure AD User ImmutableId Attribute Updated
    description: Detects modifications to the SourceAnchor (ImmutableId) attribute for an Azure Active Directory user, indicating a potential identity federation backdoor setup.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - cloud
      - azure
      - azure:monitor:aad
  - title: Detect Azure AD User ImmutableId Attribute Updated by Unusual Actor
    description: Detects modifications to the SourceAnchor (ImmutableId) attribute for an Azure Active Directory user by an unusual actor.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - cloud
      - azure
      - azure:monitor:aad
rules_count: 2
---

This threat brief focuses on the detection of malicious modifications to the `SourceAnchor` (ImmutableId) attribute within Azure Active Directory (Azure AD). This attribute, when altered by an attacker, can facilitate the creation of a backdoor for identity federation, potentially leading to persistent unauthorized access. The activity is detected via Azure AD audit logs, specifically monitoring "Update user" operations targeting the `SourceAnchor` attribute. The technique is particularly relevant for defenders because a successful modification enables an attacker to impersonate any user within the organization, circumventing standard authentication measures like passwords and multi-factor authentication (MFA). Successful exploitation could result in unauthorized data access, privilege escalation, and significant data breaches. This technique has been associated with APT29.

## Attack Chain

1.  The attacker gains initial access to an account with sufficient privileges to modify Azure AD user attributes, potentially through compromised credentials or phishing.
2.  The attacker uses the compromised account to access the Azure portal or uses PowerShell with the Azure AD module.
3.  The attacker identifies a target user account within Azure AD for which they want to establish persistent access.
4.  The attacker modifies the `SourceAnchor` attribute (ImmutableId) of the target user account. This attribute is intended for on-premises Active Directory synchronization and is not typically changed directly in Azure AD.
5.  The attacker configures a rogue identity provider (IdP) with claims matching the modified `SourceAnchor` value of the target user.
6.  The attacker establishes a federation trust between the rogue IdP and the Azure AD tenant, allowing the attacker to assert authentication for the target user.
7.  The attacker authenticates to the rogue IdP using attacker-controlled credentials.
8.  The rogue IdP generates a SAML token with the forged `SourceAnchor` claim, allowing the attacker to bypass normal Azure AD authentication controls and gain access to the target user's resources. The final objective is to maintain persistence and impersonate the target user.

## Impact

Successful modification of the `SourceAnchor` attribute allows attackers to bypass password and MFA requirements, impersonating any user within the organization. This can lead to unauthorized access to sensitive data, privilege escalation, and potentially significant data breaches. If an attacker successfully establishes this backdoor, the compromise can persist undetected for extended periods, causing widespread damage.

## Recommendation

*   Deploy the Sigma rule `Detect Azure AD User ImmutableId Attribute Updated` to your SIEM to detect modifications to the `SourceAnchor` attribute (Azure Active Directory Update user).
*   Investigate and filter legitimate uses of `SourceAnchor` attribute modifications, as identified in the `known_false_positives` section.
*   Monitor Azure AD audit logs for "Update user" operations, specifically targeting the `properties.targetResources{}.modifiedProperties{}.displayName=SourceAnchor` event, as described in the `search` query.
*   Review the references provided, especially the Mandiant report on remediation strategies for Microsoft 365 to defend against APT29, to understand the broader context of this attack technique and potential mitigation strategies (https://www.mandiant.com/resources/remediation-and-hardening-strategies-microsoft-365-defend-against-apt29-v13).
