---
title: Azure AD Activity From Anonymous IP Address
slug: 2024-01-09-azure-anonymous-ip
description: Detection of user activity originating from an IP address identified as an anonymous proxy, potentially indicating unauthorized access, privilege escalation, or persistence within an Azure Active Directory environment.
date: "2024-01-09T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azuread
  - anonymous-proxy
  - identity-protection
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#activity-from-anonymous-ip-address
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins
rules:
  - title: Azure AD Risky IP Address Activity
    description: Detects sign-ins from IP addresses flagged as anonymous proxies in Azure AD Identity Protection.
    platform: sigma
    severity: high
    tactics:
      - stealth
    techniques:
      - T1078
    data_sources:
      - azure
      - riskdetection
  - title: Azure AD Activity from Unfamiliar Country
    description: Detects sign-ins from countries/regions not usually accessed by the user
    platform: sigma
    severity: medium
    tactics:
      - initial-access
      - stealth
    techniques:
      - T1078
    data_sources:
      - azure
      - riskdetection
rules_count: 2
---

This threat brief focuses on identifying malicious activity within Azure Active Directory environments where users are observed originating traffic from anonymous IP addresses. These IP addresses are typically associated with VPNs, Tor exit nodes, or proxy services, often used by threat actors to obfuscate their true location and evade detection. The activity is flagged within Azure AD Identity Protection as a 'riskyIPAddress'. Detecting and investigating these events is crucial, as they often precede or accompany other malicious behaviors such as account compromise, privilege escalation, and data exfiltration. It allows defenders to proactively identify and respond to potential security incidents before significant damage occurs.

## Attack Chain

1.  The attacker gains initial access to an Azure AD user account through various means, such as credential theft, phishing, or brute-force attacks.
2.  The attacker leverages an anonymous proxy service (e.g., VPN, Tor) to mask their true IP address and location.
3.  The compromised user account is used to sign in to Azure AD from the anonymous IP address.
4.  Azure AD Identity Protection flags the sign-in attempt as 'riskyIPAddress'.
5.  The attacker attempts to escalate privileges within the Azure AD environment, potentially targeting sensitive roles or resources.
6.  The attacker may attempt to establish persistence by creating new user accounts or modifying existing ones.
7.  The attacker may then try to access sensitive data or resources within the Azure AD environment.
8.  Finally, the attacker exfiltrates sensitive data or launches further attacks against other systems within the organization's network.

## Impact

A successful attack leveraging anonymous IP addresses can lead to significant damage, including unauthorized access to sensitive data, compromise of critical systems, and financial losses. The use of anonymous proxies makes attribution and incident response more difficult, potentially prolonging the duration of the attack. Organizations may experience data breaches, reputational damage, and regulatory fines as a result of such attacks.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect 'riskyIPAddress' events in Azure AD logs.
*   Investigate any sign-in events flagged as 'riskyIPAddress' in the context of other sign-ins from the same user to identify potential account compromise.
*   Implement multi-factor authentication (MFA) for all users to reduce the risk of account compromise.
*   Review and enforce conditional access policies to restrict access from untrusted locations or devices.
*   Monitor Azure AD audit logs for suspicious activity, such as changes to user accounts, group memberships, or application permissions.
