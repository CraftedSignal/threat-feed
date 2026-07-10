---
title: Azure AD Brute Force Attack Detected
slug: 2024-01-azuread-bruteforce
description: An IP address with 20 or more failed authentication attempts to an Azure AD tenant within 10 minutes, indicative of a brute force attack targeting user accounts in Azure Active Directory.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - brute-force
  - credential-access
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://attack.mitre.org/techniques/T1110/
  - https://attack.mitre.org/techniques/T1110/001/
  - https://attack.mitre.org/techniques/T1110/003/
  - https://github.com/splunk/security_content/blob/main/detections/cloud/azure_ad_high_number_of_failed_authentications_from_ip.yml
rules:
  - title: Azure AD High Number of Failed Authentications From Single IP
    description: Detects a high number of failed Azure AD authentication attempts from a single IP address within a short timeframe, indicating potential brute-force activity.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.001
      - T1110.003
    data_sources:
      - authentication
      - azure_ad
  - title: Azure AD Failed Authentication with Non-Existent User
    description: Detects failed authentication attempts in Azure AD where the username does not exist, which is often seen in credential stuffing attacks.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110.003
    data_sources:
      - authentication
      - azure_ad
rules_count: 2
---

This brief addresses the detection of potential brute force attacks against Azure Active Directory (Azure AD) environments. The focus is on identifying IP addresses exhibiting a high number of failed authentication attempts within a short timeframe. Specifically, the alert triggers when an IP address records 20 or more failed login attempts to an Azure AD tenant within a 10-minute window. This activity is a strong indicator of attackers attempting to guess user credentials to gain unauthorized access. The campaign targets user accounts within the Azure AD environment. Successful compromise can lead to unauthorized access to sensitive data, resources, and services within the Azure cloud.

## Attack Chain

1.  **Initial Access:** The attacker attempts to gain initial access by targeting Azure AD accounts with a list of common or known credentials. (T1110.001)
2.  **Credential Guessing:** The attacker initiates a series of authentication requests to Azure AD, systematically attempting different usernames and passwords.
3.  **Failed Authentication Attempts:** The authentication attempts fail, generating SignInLogs with errorCode 50126 and 'succeeded=false' status.
4.  **IP Address Aggregation:** The attacker's source IP address is recorded with each failed login attempt within the Azure AD SignInLogs.
5.  **Threshold Trigger:** The number of failed authentication attempts from the same IP address exceeds the defined threshold of 20 within a 10-minute window.
6.  **Potential Account Lockout:** Repeated failed attempts may lead to account lockouts, causing disruption for legitimate users and potentially triggering security alerts.
7.  **Successful Authentication (If Successful):** If the attacker correctly guesses a valid credential, they gain unauthorized access to the targeted Azure AD account.
8.  **Lateral Movement/Privilege Escalation:** Upon gaining access, the attacker may attempt to move laterally within the Azure environment or escalate privileges to access more sensitive resources.

## Impact

A successful brute force attack can lead to the compromise of user accounts within Azure Active Directory. This can result in unauthorized access to sensitive information stored in cloud services, such as Microsoft 365, Azure VMs, and other integrated applications. The potential impact includes data breaches, financial loss, and reputational damage. Organizations with weak password policies or inadequate monitoring of authentication activity are particularly vulnerable.

## Recommendation

*   Deploy the provided Sigma rule `Azure AD High Number of Failed Authentications From IP` to your SIEM to detect brute force attempts based on failed login events.
*   Investigate any alerts triggered by the `Azure AD High Number of Failed Authentications From IP` rule, focusing on the source IP address and the targeted user accounts.
*   Implement multi-factor authentication (MFA) for all users to significantly reduce the risk of successful credential compromise.
*   Enforce strong password policies, including minimum length, complexity requirements, and regular password resets, to mitigate the effectiveness of password guessing attacks (T1110.001, T1110.003).
*   Review and tune the threshold (20 failed attempts) in the `Azure AD High Number of Failed Authentications From IP` rule to align with your organization's baseline authentication activity and risk tolerance.
*   Monitor Azure AD sign-in logs for unusual patterns or anomalies that may indicate ongoing attacks.
