---
title: Azure PIM Role Activation Without MFA
slug: 2024-01-azure-pim-no-mfa
description: Detection of Azure Privileged Identity Management (PIM) roles being activated without requiring multi-factor authentication, potentially leading to unauthorized privilege escalation and persistence.
date: "2024-01-03T18:23:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - azure
  - pim
  - mfa
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#roles-dont-require-multi-factor-authentication-for-activation
  - https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/azure/privileged_identity_management/azure_pim_role_no_mfa_required.yml
rules:
  - title: Azure PIM Role Activated Without MFA
    description: Detects when a privileged role is activated in Azure PIM without MFA.
    platform: sigma
    severity: high
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078
    data_sources:
      - azure
      - pim
  - title: Possible PIM Role Activation
    description: Detects events related to possible PIM role activations, useful for baselining
    platform: sigma
    severity: informational
    tactics:
      - initial-access
      - persistence
      - privilege-escalation
      - stealth
    techniques:
      - T1078
    data_sources:
      - azure
      - pim
rules_count: 2
---

The absence of multi-factor authentication (MFA) during the activation of privileged roles in Azure Privileged Identity Management (PIM) poses a significant security risk. When roles can be activated without MFA, attackers who have already compromised a user account can escalate their privileges without needing to bypass an MFA challenge. This scenario circumvents a critical security control, making the environment vulnerable to lateral movement, data exfiltration, and other malicious activities. This brief is based on Sigma rule 94a66f46-5b64-46ce-80b2-75dcbe627cc0, published on 2023-09-14. Defenders need to monitor PIM configurations to ensure that MFA is enforced for all privileged role activations, mitigating the risk of unauthorized access and privilege escalation.

## Attack Chain

1.  An attacker gains initial access to a user account, potentially through phishing or credential stuffing.
2.  The attacker identifies a privileged role within Azure PIM that the compromised user is eligible to activate.
3.  The attacker attempts to activate the privileged role using the compromised user's credentials.
4.  Due to misconfiguration, MFA is not required for the role activation process.
5.  The attacker successfully activates the privileged role without providing a second factor of authentication.
6.  The attacker leverages the newly acquired privileges to access sensitive resources and data within the Azure environment.
7.  The attacker performs malicious actions such as creating new accounts, modifying configurations, or exfiltrating data.
8.  The attacker establishes persistence by creating backdoors or modifying access control policies.

## Impact

The absence of MFA during PIM role activation can lead to significant damage, potentially affecting all resources within the Azure environment accessible to the compromised privileged role. Successful exploitation allows attackers to bypass a critical security control, leading to privilege escalation, data breaches, and system compromise. The impact spans data confidentiality, integrity, and availability, and could result in regulatory fines, reputational damage, and financial losses.

## Recommendation

*   Deploy the Sigma rule "Roles Activation Doesn't Require MFA" to your SIEM and tune for your environment to detect instances where privileged roles are activated without MFA based on `riskEventType: 'noMfaOnRoleActivationAlertIncident'` in Azure PIM logs.
*   Review and enforce MFA policies for all privileged role activations within Azure PIM, as recommended in the Microsoft documentation ([https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#roles-dont-require-multi-factor-authentication-for-activation](https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-configure-security-alerts#roles-dont-require-multi-factor-authentication-for-activation)).
