---
title: Azure AD User Consent Blocked for Risky Application
slug: 2024-01-03-azuread-risky-consent
description: Azure AD blocked a user's attempt to grant consent to a risky application, indicating potential OAuth abuse and requiring investigation of the user and application involved.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azuread
  - oauth
  - consent-phishing
  - cloud
vendors:
  - Microsoft
products:
  - Azure Active Directory
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1528
    technique_name: Steal Application Access Token
references:
  - https://attack.mitre.org/techniques/T1528/
  - https://www.microsoft.com/en-us/security/blog/2022/09/22/malicious-oauth-applications-used-to-compromise-email-servers-and-spread-spam/
  - https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/protect-against-consent-phishing
  - https://learn.microsoft.com/en-us/defender-cloud-apps/investigate-risky-oauth
  - https://www.alteredsecurity.com/post/introduction-to-365-stealer
  - https://github.com/AlteredSecurity/365-Stealer
rules:
  - title: Azure AD User Consent Blocked for Risky Application
    description: Detects instances where Azure AD has blocked a user's attempt to grant consent to a risky application.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1528
    data_sources:
      - audit
      - azure
  - title: Azure AD Consent to Application with Risky Permissions
    description: Detects instances of consent to applications requesting high-risk permissions in Azure AD.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1528
    data_sources:
      - audit
      - azure
rules_count: 2
---

This analytic identifies instances where Azure Active Directory (Azure AD) has automatically blocked a user's attempt to grant consent to an application flagged as risky. The detection focuses on the "Consent to application" operation within Azure AD audit logs, specifically looking for system-driven block events. This automated blocking mechanism is a crucial defense against malicious OAuth applications attempting to gain unauthorized access to organizational data. Early detection of these blocked consent attempts allows security teams to investigate potentially compromised user accounts and identify malicious applications targeting their organization. The observed activity highlights Azure's proactive security measures and emphasizes the need for immediate investigation to understand the context and take preventive measures against sophisticated consent phishing attacks, particularly those leveraging techniques similar to the 365-Stealer.

## Attack Chain

1.  Attacker registers a malicious OAuth application in Azure AD.
2.  The attacker crafts a phishing email or uses other social engineering methods to lure a target user into clicking a malicious link.
3.  The link redirects the user to the Azure AD consent page for the attacker's malicious application.
4.  The user, if not cautious, is prompted to grant the application permissions to access their account and data.
5.  Azure AD's risk analysis engine detects that the application is risky based on various factors (e.g., publisher reputation, requested permissions).
6.  Azure AD blocks the user's attempt to grant consent to the application.
7.  The event is logged in the Azure AD audit logs with a "failure" result and a reason indicating "Risky application detected".
8.  Security team investigates the blocked consent attempt, the user involved, and the characteristics of the flagged application.

## Impact

A successful consent phishing attack can lead to the compromise of user accounts, data exfiltration, and further malicious activities within the organization. While Azure AD's blocking mechanism prevents immediate compromise, repeated attempts or successful circumvention could lead to significant damage. This detection helps identify users who are being targeted and applications that are attempting to infiltrate the organization, reducing the potential for widespread damage.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune it for your specific Azure AD environment to detect blocked consent attempts for risky applications (`rules`).
*   Investigate any triggered alerts by examining the user, application, and requested permissions involved to determine the potential impact (`search`).
*   Review Azure AD Identity Protection settings to ensure that risk-based consent policies are properly configured and blocking risky applications (`references`).
*   Educate users about the risks of granting consent to unfamiliar applications and how to identify potentially malicious requests (`references`).
