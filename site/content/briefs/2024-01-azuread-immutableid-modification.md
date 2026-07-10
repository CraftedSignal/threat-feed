---
title: Azure AD User ImmutableId Attribute Modification for Persistence
slug: 2024-01-azuread-immutableid-modification
description: Attackers modify the ImmutableID attribute of an Azure AD user to establish a federation backdoor, bypassing MFA and enabling persistent access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - azuread
  - persistence
  - federation
  - immutabilid
vendors:
  - Microsoft
products:
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
  - title: Azure AD User ImmutableId Attribute Updated
    description: Detects modifications to the SourceAnchor (ImmutableId) attribute for an Azure Active Directory user, which can indicate an attempt to establish a federation backdoor.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - cloudtrail
      - azure
      - o365
  - title: Azure AD ImmutableId Reset to Null
    description: Detects when the ImmutableId of an Azure AD user is reset to null which could indicate an attempt to remove a compromised federation backdoor.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - cloudtrail
      - azure
      - o365
rules_count: 2
---

Attackers are targeting Azure Active Directory (Azure AD) environments to establish persistent backdoors. This involves manipulating the `SourceAnchor` attribute, also known as `ImmutableId`, of a user object within Azure AD. This manipulation allows an attacker to forge authentication and bypass Multi-Factor Authentication (MFA) for the targeted user. Successful exploitation allows the attacker to impersonate any user. Defenders should monitor changes to the `SourceAnchor` attribute for unusual activity. This activity is a common step in setting up an Azure AD identity federation backdoor, allowing an adversary to establish persistence.

## Attack Chain

1. The attacker gains initial access to an account with sufficient privileges to modify Azure AD user attributes.
2. The attacker identifies a target user account within the Azure AD tenant.
3. The attacker modifies the `SourceAnchor` (ImmutableId) attribute of the target user's account using Azure AD PowerShell or the Azure portal.
4. The attacker configures a malicious Security Assertion Markup Language (SAML) identity provider.
5. The attacker crafts a SAML assertion with the target user's `ImmutableId` and signs it with the malicious identity provider.
6. The attacker uses the crafted SAML assertion to authenticate to Azure AD as the target user, bypassing password and MFA requirements.
7. The attacker gains unauthorized access to resources and data within the Azure AD environment.
8. The attacker maintains persistent access to the compromised user account, even if the user's password is changed or MFA is enabled.

## Impact

Successful modification of the ImmutableId attribute allows attackers to bypass password and MFA protections, leading to full account compromise. An attacker with the ability to impersonate a privileged user can escalate privileges, access sensitive data, and disrupt critical business operations. This can lead to data breaches, financial loss, and reputational damage.

## Recommendation

*   Deploy the Sigma rule `Azure AD User ImmutableId Attribute Updated` to your SIEM and tune for your environment.
*   Enable Azure AD audit logging and monitor for "Update user" operations targeting the `SourceAnchor` attribute.
*   Investigate any modifications to the `SourceAnchor` attribute, especially those performed by unfamiliar or unauthorized accounts.
*   Review and harden Azure AD federation settings to prevent the use of malicious SAML identity providers.
*   Monitor and investigate user accounts identified in the `RBA message` in the alert description.
