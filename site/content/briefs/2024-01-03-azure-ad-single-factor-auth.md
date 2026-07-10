---
title: Azure AD Successful Single-Factor Authentication
slug: 2024-01-03-azure-ad-single-factor-auth
description: Successful single-factor authentication events against Azure Active Directory are identified using Azure SignInLogs data, which may indicate misconfiguration, policy violation, or potential account takeover leading to data breaches and privilege escalation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azuread
  - single-factor authentication
  - account takeover
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1586
    technique_name: Compromise Appliance
references:
  - https://attack.mitre.org/techniques/T1078/004/
  - https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks*
  - https://www.forbes.com/sites/daveywinder/2020/07/08/new-dark-web-audit-reveals-15-billion-stolen-logins-from-100000-breaches-passwords-hackers-cybercrime/?sh=69927b2a180f
rules:
  - title: Azure AD Successful Single Factor Authentication
    description: Detects successful single-factor authentication events in Azure AD, potentially indicating account compromise.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1078.004
    data_sources:
      - authentication
      - azure
  - title: Azure AD Single Factor Auth from Unusual Location
    description: Detects single factor authentication events from locations not normally seen for a user.
    platform: sigma
    severity: low
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1078.004
    data_sources:
      - authentication
      - azure
rules_count: 2
---

This analytic identifies successful single-factor authentication events against Azure Active Directory. It leverages Azure SignInLogs data, specifically focusing on events where single-factor authentication succeeded. This activity is significant as it may indicate a misconfiguration, policy violation, or potential account takeover attempt. An attacker gaining unauthorized access to the account, potentially leading to data breaches, privilege escalation, or further exploitation within the environment. Multi-factor authentication (MFA) is a crucial security control, and its absence can significantly increase the risk of account compromise. The analytic focuses on Azure AD events and is designed to detect deviations from expected authentication patterns.

## Attack Chain

1. Initial Access: The attacker gains initial access to a valid username and password through phishing, credential stuffing, or purchasing stolen credentials.
2. Attempt Authentication: The attacker attempts to authenticate to Azure AD using the compromised credentials, bypassing MFA if it is not enabled or configured correctly.
3. Single-Factor Authentication Success: Azure AD logs a successful single-factor authentication event, indicating that the attacker has gained access without additional verification.
4. Reconnaissance: Once authenticated, the attacker performs reconnaissance activities within the Azure AD environment, gathering information about users, groups, and resources.
5. Privilege Escalation: The attacker attempts to escalate privileges by exploiting misconfigurations or vulnerabilities within Azure AD or related services.
6. Lateral Movement: The attacker moves laterally to other systems and applications within the organization's environment, leveraging the compromised account's access rights.
7. Data Exfiltration: The attacker accesses and exfiltrates sensitive data from cloud storage, databases, or applications accessible with the compromised credentials.
8. Persistence: The attacker establishes persistence by creating new user accounts, modifying existing ones, or deploying malicious applications within Azure AD.

## Impact

A successful single-factor authentication attack can lead to significant damage, including unauthorized access to sensitive data, privilege escalation, and lateral movement within the organization's cloud environment. The absence of MFA makes accounts vulnerable to credential-based attacks. The impact could include data breaches, financial loss, and reputational damage. Many organizations now require this as part of compliance frameworks.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect successful single-factor authentication events in Azure AD logs (Azure Active Directory, `azure_monitor_aad`).
*   Review and enforce multi-factor authentication (MFA) policies for all users and applications in Azure AD to prevent unauthorized access (https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks*).
*   Investigate any detected successful single-factor authentication events to determine if they are legitimate or indicative of malicious activity (Azure Active Directory, `azure_monitor_aad`).
*   Monitor user activity for signs of reconnaissance, privilege escalation, and lateral movement following a successful single-factor authentication event (Azure Active Directory, `azure_monitor_aad`).
