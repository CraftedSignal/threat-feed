---
title: M365 Identity Login from Impossible Travel Location
slug: 2024-09-m365-impossible-travel
description: Detects successful Microsoft 365 portal logins from impossible travel locations, defined as logins originating from two different countries within a short timeframe, potentially indicating account compromise or unauthorized access.
date: "2024-09-04T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - identity
  - microsoft 365
  - initial access
vendors:
  - Microsoft
products:
  - Microsoft 365
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://www.huntress.com/blog/time-travelers-busted-how-to-detect-impossible-travel-
rules:
  - title: M365 Identity Login from Impossible Travel Location
    description: Detects successful Microsoft 365 portal logins from impossible travel locations (different countries within a short time frame).
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1078.004
    data_sources:
      - webserver
      - linux
  - title: M365 Identity Login from Impossible Travel Location - Process Creation Filter
    description: Detects processes initiating logins from different countries within a short time frame.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1078.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies suspicious Microsoft 365 login activity indicative of "impossible travel," where a user successfully logs in from two geographically distant locations (different countries) within a short timeframe (e.g., 15 minutes). This behavior is often associated with account compromise, where an attacker gains unauthorized access to a legitimate user's credentials and attempts to access resources from a different location. The rule focuses on Azure Active Directory (Entra ID) logins and filters out specific application IDs and request types known to cause false positives. This detection is crucial for identifying and responding to potential breaches of M365 accounts, which can lead to data exfiltration, business email compromise (BEC), or other malicious activities. This behavior can be easily missed without automated detection because legitimate users should not be able to log in from geographically distant locations within a short time.

## Attack Chain

1.  **Credential Compromise:** The attacker obtains valid credentials for a Microsoft 365 account, possibly through phishing, credential stuffing, or malware.
2.  **Initial Login (Location A):** The attacker uses the compromised credentials to successfully log into the Microsoft 365 portal from Country A. This generates a UserLoggedIn event with outcome:success in the Azure Active Directory audit logs.
3.  **Privilege Escalation (Conditional):** If the compromised account has elevated privileges, the attacker may attempt to escalate their privileges within the Microsoft 365 environment. This activity is not directly covered by this rule, but it can happen after the initial access.
4.  **Lateral Movement (Conditional):** After gaining initial access, the attacker may attempt to move laterally within the Microsoft 365 environment, accessing other user accounts or resources. This activity is not directly covered by this rule, but it can happen after the initial access.
5.  **Login from New Location (Location B):** Within a short timeframe (e.g., 15 minutes), the attacker initiates a new login attempt from Country B, which is geographically distant from Country A. This generates another UserLoggedIn event with outcome:success.
6.  **Data Exfiltration or Malicious Activity:** Having gained access, the attacker performs malicious activities such as exfiltrating sensitive data, sending phishing emails, or modifying critical configurations within the Microsoft 365 environment.
7.  **Persistence:** The attacker may attempt to establish persistence within the compromised account, such as creating new mailbox rules or modifying authentication settings to maintain access even if the password is changed. This activity is not directly covered by this rule, but it can happen after the initial access.

## Impact

A successful "impossible travel" attack can lead to significant consequences, including unauthorized access to sensitive data, business email compromise (BEC), financial loss, and reputational damage. The number of affected users and the severity of the impact depend on the privileges associated with the compromised account and the attacker's objectives. Organizations across all sectors are vulnerable to this type of attack, particularly those relying heavily on Microsoft 365 for communication, collaboration, and data storage. A successful breach can result in regulatory fines, legal liabilities, and a loss of customer trust.

## Recommendation

*   Deploy the Sigma rule "M365 Identity Login from Impossible Travel Location" to your SIEM to detect suspicious login patterns indicative of impossible travel.
*   Tune the threshold settings in the Sigma rule "M365 Identity Login from Impossible Travel Location" to minimize false positives based on your organization's travel patterns and VPN usage.
*   Review and enhance multi-factor authentication (MFA) policies for all users, especially those with privileged accounts, to mitigate the risk of credential compromise.
*   Investigate and remediate any identified "impossible travel" events promptly, following the triage and analysis steps outlined in the rule's documentation.
*   Monitor user activity for signs of lateral movement, privilege escalation, and data exfiltration following any detected "impossible travel" events.
