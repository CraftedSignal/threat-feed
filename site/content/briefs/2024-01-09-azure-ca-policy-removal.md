---
title: Unauthorized Removal of Azure Conditional Access Policy
slug: 2024-01-09-azure-ca-policy-removal
description: An unauthorized actor removes a Conditional Access policy in Azure, potentially weakening the organization's security posture and enabling privilege escalation or credential access.
date: "2024-01-09T15:00:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - azure
  - conditional-access
  - privilege-escalation
  - credential-access
  - persistence
  - defense-impairment
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: 'Impair Defenses: Disable or Modify Tools'
references:
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-infrastructure#conditional-access
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/audit_logs/azure_aad_secops_ca_policy_removedby_bad_actor.yml
rules:
  - title: Azure AD CA Policy Removed
    description: Detects the removal of a Conditional Access policy in Azure AD.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
      - defense-impairment
      - persistence
      - privilege-escalation
    techniques:
      - T1548
      - T1556
    data_sources:
      - azure
      - auditlogs
  - title: Azure AD CA Policy Modification
    description: Detects modification of a Conditional Access policy in Azure AD.
    platform: sigma
    severity: low
    tactics:
      - defense-impairment
    techniques:
      - T1562.001
    data_sources:
      - azure
      - auditlogs
rules_count: 2
---

The unauthorized removal of a Conditional Access (CA) policy in Azure Active Directory can significantly weaken an organization's security posture. Conditional Access policies are critical for enforcing multi-factor authentication, device compliance, and other security controls based on user, location, device, and application conditions. When a non-approved actor removes such a policy, it can open the door for privilege escalation, credential access, and persistence by malicious actors. This activity is often performed after an initial compromise to disable security controls and move laterally within the environment. Identifying and responding to such removals promptly is essential to maintain a strong security posture.

## Attack Chain

1.  Initial Access: The attacker gains initial access to an account with sufficient privileges to view and modify Azure Active Directory settings. This could be through phishing, password spraying, or exploiting a vulnerability.
2.  Privilege Escalation: The attacker escalates privileges within Azure AD to gain the necessary permissions to manage Conditional Access policies. This might involve adding themselves to a privileged role or exploiting misconfigurations in existing roles.
3.  Discovery: The attacker enumerates existing Conditional Access policies to identify targets for removal. They may focus on policies that enforce MFA or restrict access based on location.
4.  Defense Evasion: The attacker disables or modifies logging configurations to reduce the likelihood of detection.
5.  Policy Removal: The attacker removes the targeted Conditional Access policy using the Azure portal, PowerShell, or the Azure CLI. The audit logs will record a "Delete conditional access policy" event.
6.  Credential Access: With the CA policy removed, the attacker may attempt to access sensitive resources or applications without MFA, potentially gaining access to credentials or sensitive data.
7.  Persistence: The attacker establishes persistence by creating new user accounts or modifying existing ones to maintain access even if their initial entry point is discovered.
8.  Lateral Movement: The attacker leverages the compromised credentials and weakened security controls to move laterally to other systems and resources within the organization.

## Impact

A successful removal of a Conditional Access policy can lead to widespread compromise. Attackers can bypass multi-factor authentication, gain unauthorized access to sensitive data, and escalate privileges within the organization. The impact can range from data breaches and financial losses to reputational damage and compliance violations. Depending on the scope of the compromised policy, the number of affected users could range from dozens to thousands.

## Recommendation

*   Deploy the provided Sigma rule to detect the "Delete conditional access policy" event in Azure audit logs, indicating a CA policy removal.
*   Regularly review and audit Azure Active Directory role assignments to minimize the risk of unauthorized privilege escalation.
*   Implement multi-factor authentication for all user accounts, especially those with administrative privileges.
*   Monitor Azure audit logs for unusual activity, such as changes to user accounts, role assignments, and Conditional Access policies.
*   Investigate any detected instances of CA policy removal to determine the scope of the compromise and take appropriate remediation steps.
*   Review and harden Conditional Access policies to ensure they are effectively protecting critical resources and applications.
