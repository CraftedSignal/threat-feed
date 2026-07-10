---
title: Azure AD Authentication Failed During MFA Challenge
slug: 2024-01-azure-ad-failed-mfa
description: Detection of failed authentication attempts against an Azure AD tenant during the MFA challenge, specifically flagged by error code 500121, leveraging Azure AD SignInLogs, which may indicate an adversary attempting to authenticate using compromised credentials on an account with MFA enabled, potentially leading to unauthorized access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azuread
  - mfa
  - credential-access
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1586
    technique_name: Compromise Appliances
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1621
    technique_name: Multi-Factor Authentication Request Forgery
references:
  - https://attack.mitre.org/techniques/T1621/
  - https://attack.mitre.org/techniques/T1078/004/
  - https://docs.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks
  - https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details
rules:
  - title: Azure AD Failed MFA Challenge
    description: Detects failed Azure AD authentication attempts during MFA challenge based on error code 500121.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1078.004
      - T1621
    data_sources:
      - authentication
      - azure_ad
  - title: Azure AD Repeated Failed MFA Attempts
    description: Detects repeated failed MFA attempts from the same IP address within a short timeframe, potentially indicating brute-forcing.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1078.004
      - T1621
    data_sources:
      - authentication
      - azure_ad
  - title: Azure AD Failed MFA with Uncommon User Agent
    description: Detects failed MFA attempts with error code 500121 using an uncommon user agent string, which might be associated with malicious tools or scripts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1078.004
      - T1621
    data_sources:
      - authentication
      - azure_ad
rules_count: 3
---

This brief focuses on identifying potentially malicious activity within Azure Active Directory (Azure AD) environments. It centers around the detection of failed authentication attempts during the Multi-Factor Authentication (MFA) challenge, as indicated by error code 500121 in the Azure AD SignInLogs. This activity is particularly concerning because it may signal that an attacker is trying to gain unauthorized access to an account that has MFA enabled, suggesting credential compromise and an active attempt to bypass security controls. The detection leverages the `azure:monitor:aad` sourcetype and SignInLogs category within Splunk environments. Understanding and detecting these failed MFA attempts is crucial for defenders to quickly identify and respond to potential account takeover attempts, preventing further compromise.

## Attack Chain

1.  **Credential Compromise:** The attacker obtains valid credentials for an Azure AD user account, potentially through phishing (T1566), credential stuffing, or malware.
2.  **Initial Authentication Attempt:** The attacker uses the compromised credentials to initiate a login attempt to a resource protected by Azure AD.
3.  **MFA Challenge Triggered:** Because the account has MFA enabled, Azure AD triggers an MFA challenge, requiring the attacker to provide a second factor of authentication.
4.  **Failed MFA Attempt (Error 500121):** The attacker fails to provide the correct MFA response, resulting in an error code 500121 in the Azure AD SignInLogs.
5.  **Repeated Failed Attempts:** The attacker may repeat the failed authentication attempts multiple times, potentially trying different methods or waiting for a legitimate user to inadvertently approve the request.
6.  **Account Lockout (Possible):** After multiple failed attempts, the account may be temporarily locked out, depending on the configured lockout policies.
7.  **Bypass MFA (Alternative):** In some cases, the attacker might attempt to bypass MFA through techniques like MFA fatigue or push notification spamming. (T1621)

## Impact

Successful exploitation can lead to a full account takeover, allowing the attacker to access sensitive data, applications, and resources within the Azure AD environment. This can result in data breaches, financial loss, disruption of services, and reputational damage. The impact is amplified if the compromised account has elevated privileges, such as administrative roles. The references suggest that identifying and addressing this type of activity is crucial for preventing unauthorized access and further compromise.

## Recommendation

*   Deploy the provided Sigma rule `Azure AD Failed MFA Challenge` to detect failed authentication attempts with error code 500121 in your SIEM, tuning it for your environment.
*   Investigate any alerts generated by the Sigma rule by examining the source IP address (`src`) and user (`user`) involved in the failed authentication attempts, referencing the Azure AD SignInLogs.
*   Review and harden MFA policies, including lockout policies and approved authentication methods, based on Microsoft's MFA guidance.
*   Monitor for related risk events for users with failed MFA challenges, as highlighted in the drilldown searches within the original Splunk detection.
*   Implement user training programs to educate users about phishing and other techniques used to compromise credentials and bypass MFA.
