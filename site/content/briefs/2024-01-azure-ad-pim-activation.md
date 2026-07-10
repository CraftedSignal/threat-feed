---
title: Azure AD PIM Role Activation Detection
slug: 2024-01-azure-ad-pim-activation
description: Detection of Azure AD Privileged Identity Management (PIM) role activation, indicating potential privilege escalation or unauthorized access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - pim
  - privilege-escalation
  - persistence
vendors:
  - Microsoft
products:
  - Azure Active Directory
  - Privileged Identity Management
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
  - https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-configure
  - https://learn.microsoft.com/en-us/azure/active-directory/privileged-identity-management/pim-how-to-activate-role
  - https://microsoft.github.io/Azure-Threat-Research-Matrix/PrivilegeEscalation/AZT401/AZT401/
rules:
  - title: Azure AD PIM Role Activated
    description: Detects the activation of an Azure AD Privileged Identity Management (PIM) role.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - audit
      - azure
  - title: Azure AD PIM Activation by Unusual User
    description: Detects PIM role activation by a user not typically associated with administrative tasks.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - audit
      - azure
rules_count: 2
---

This brief focuses on detecting the activation of Azure AD Privileged Identity Management (PIM) roles, a critical security concern. PIM allows users to activate elevated privileges on demand, but unauthorized or malicious activation can lead to significant security breaches. The detection leverages Azure Active Directory audit logs, specifically targeting the "Add member to role completed (PIM activation)" event. Successful exploitation can enable adversaries to perform administrative actions, exfiltrate sensitive data, or further compromise the Azure environment. Defenders should closely monitor PIM role activations to identify and respond to potentially malicious activity. The analytic is designed for use with the azure:monitor:aad sourcetype, which uses the AuditLog log category.

## Attack Chain

1.  An attacker gains initial access to a user account within the Azure AD environment (e.g., through phishing or credential stuffing).
2.  The attacker identifies a PIM role that would grant them elevated privileges necessary to achieve their objectives.
3.  The attacker attempts to activate the targeted PIM role. This triggers an "Add member to role completed (PIM activation)" event in the Azure AD audit logs.
4.  Azure AD validates the activation request based on configured policies (e.g., MFA, approval workflows).
5.  If the activation is successful, the attacker's account is temporarily granted the privileges associated with the PIM role.
6.  The attacker leverages the elevated privileges to perform malicious actions, such as creating new user accounts with administrative rights, modifying security policies, or accessing sensitive data.
7.  The attacker attempts to maintain persistence by creating backdoors or modifying existing configurations to ensure continued access even after the PIM role expires.
8.  The attacker achieves their final objective, which may include data exfiltration, service disruption, or further lateral movement within the Azure environment.

## Impact

Successful exploitation can lead to unauthorized administrative actions, data breaches, or further compromise of the Azure environment. The number of potential victims depends on the scope of the compromised account and the permissions granted by the activated PIM role. Industries relying heavily on Azure AD for identity and access management are particularly vulnerable. The financial impact could be substantial due to data loss, regulatory fines, and incident response costs.

## Recommendation

*   Deploy the Sigma rule `Azure AD PIM Role Activated` to your SIEM to detect unauthorized PIM role activations based on the "Add member to role completed (PIM activation)" operation.
*   Investigate any detected PIM role activations where the `initiatedBy` field does not match expected administrative accounts.
*   Review and harden PIM policies to require multi-factor authentication (MFA) and approval workflows for role activation, as referenced in the Microsoft documentation.
*   Enable Azure AD audit log collection and ensure that the `azure:monitor:aad` sourcetype is properly configured in Splunk.
*   Use the provided drilldown searches to investigate the user and associated risk events.
