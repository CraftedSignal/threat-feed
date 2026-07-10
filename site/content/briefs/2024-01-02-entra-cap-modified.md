---
title: Entra ID Conditional Access Policy (CAP) Modified
slug: 2024-01-02-entra-cap-modified
description: An adversary may modify existing Conditional Access Policies (CAPs) in Microsoft Entra ID to weaken access controls and maintain persistence in the environment with a compromised identity.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - entra_id
  - conditional_access_policy
  - persistence
  - defense_evasion
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview
  - https://www.rezonate.io/blog/microsoft-entra-id-the-complete-guide-to-conditional-access-policies/
rules:
  - title: Entra ID Conditional Access Policy Modified
    description: Detects modifications to Conditional Access Policies in Microsoft Entra ID.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1556.009
    data_sources:
      - audit
      - azure
  - title: Entra ID Conditional Access Policy Modified by User
    description: Detects modifications to Conditional Access Policies in Microsoft Entra ID and identifies the user who initiated the change.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1556.009
    data_sources:
      - audit
      - azure
rules_count: 2
---

Microsoft Entra ID Conditional Access Policies (CAPs) are critical for enforcing secure access requirements, such as multi-factor authentication (MFA), restricting specific users or groups, and managing sign-in conditions. This analytic detects modifications to existing CAPs, which could indicate an adversary weakening an organization’s defenses to maintain persistence after initial access. The activity is identified via Azure audit logs. The modification of conditional access policies could allow unauthorized access to resources, bypass MFA, or grant excessive permissions to malicious actors. This analytic focuses on detecting these modifications, enabling security teams to respond quickly and prevent potential breaches. The rule specifically detects "Update conditional access policy" events.

## Attack Chain

1.  The adversary gains initial access to an account with sufficient privileges to modify Entra ID Conditional Access Policies.
2.  The adversary authenticates to the Azure portal or uses PowerShell/CLI with the compromised account.
3.  The adversary enumerates existing Conditional Access Policies to identify a suitable target for modification.
4.  The adversary modifies the targeted Conditional Access Policy, such as removing MFA requirements, excluding specific users or groups, or weakening other access controls.
5.  The modification is logged as an "Update conditional access policy" event in the Azure audit logs.
6.  The adversary leverages the modified policy to gain unauthorized access to resources or maintain persistence.
7.  The adversary performs actions within the environment, such as accessing sensitive data or escalating privileges.

## Impact

A successful modification of a Conditional Access Policy can lead to significant security breaches. This could include unauthorized access to sensitive data, circumvention of multi-factor authentication, and the establishment of persistent access for malicious actors. The number of affected users and resources depends on the scope of the modified policy. Organizations in all sectors are vulnerable, particularly those with extensive cloud deployments and reliance on Entra ID for identity management. If successful, the attacker could gain control over critical systems and data, leading to data breaches, financial losses, and reputational damage.

## Recommendation

*   Deploy the Sigma rule `Entra ID Conditional Access Policy Modified` to your SIEM to detect unauthorized modifications to CAPs, and tune for authorized administrative changes.
*   Review and harden Conditional Access Policies to enforce strict access controls (references: [https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview](https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/overview), [https://www.rezonate.io/blog/microsoft-entra-id-the-complete-guide-to-conditional-access-policies/](https://www.rezonate.io/blog/microsoft-entra-id-the-complete-guide-to-conditional-access-policies/)).
*   Implement stricter change management and alerting around CAP changes to ensure that all modifications are authorized and properly documented, as mentioned in the rule's documentation.
*   Regularly review user roles and permissions in Entra ID to minimize the risk of privileged account compromise.
