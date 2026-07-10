---
title: Azure AD OAuth Application Consent Granted by User
slug: 2024-01-03-azure-ad-oauth-consent
description: Detection of Azure AD OAuth application consent granted by a user, potentially leading to unauthorized access and data compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - azure
  - oauth
  - consent
  - application
  - t1528
vendors:
  - Microsoft
products:
  - Azure AD
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1528
    technique_name: Steal Application Access Token
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
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
  - title: Azure AD - OAuth Application Consent Granted
    description: Detects when a user grants consent to an OAuth application in Azure AD.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1528
    data_sources:
      - audit
      - azure
  - title: Azure AD - Suspicious OAuth App Permission Request
    description: Detects when a user grants consent to an OAuth application in Azure AD requesting high permissions.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1528
    data_sources:
      - audit
      - azure
rules_count: 2
---

This brief focuses on the threat of malicious OAuth application consent grants within Azure AD environments. Attackers may use social engineering or other techniques to trick users into granting broad permissions to attacker-controlled OAuth applications. Once consent is given, the application can access sensitive data, potentially including emails, files, and other resources, depending on the granted permissions. The detection outlined identifies instances where users have granted consent to applications, providing an opportunity to investigate potentially malicious activity. The original Splunk analytic leverages Azure AD audit logs to identify consent events. The impact of successful exploitation can range from data exfiltration to full account compromise, making proactive monitoring crucial.

## Attack Chain

1.  **Initial Compromise:** An attacker gains access to a user's email account or finds another way to interact with the target user (e.g., compromised website, malicious ad).
2.  **Crafting the Malicious Application:** The attacker creates a seemingly legitimate OAuth application within Azure AD, requesting broad permissions (e.g., access to emails, files, contacts).
3.  **Social Engineering:** The attacker crafts a phishing email or message enticing the user to grant consent to the malicious application. This may involve mimicking legitimate services or offering desirable functionality.
4.  **Consent Grant:** The user, believing the application to be trustworthy, clicks the consent link and grants the requested permissions.
5.  **Token Acquisition:** Upon consent, the attacker's application receives an access token, allowing it to access the user's resources within Azure AD.
6.  **Data Exfiltration/Abuse:** The attacker uses the access token to access sensitive data, such as emails, files, or contacts, and exfiltrates it to a remote server. The compromised application may also be used to send spam, phish other users, or perform other malicious activities.
7.  **Persistence:** Depending on the granted permissions, the attacker may be able to maintain persistent access to the user's resources even after the initial compromise is detected.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, including emails, files, and contacts. The number of affected users can vary depending on the scope of the attack. Organizations in all sectors are potentially vulnerable. The impact includes data breaches, financial loss, reputational damage, and compliance violations. Recent reports indicate a rise in OAuth-based attacks targeting cloud environments, highlighting the importance of proactive monitoring and detection.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect instances of users granting consent to OAuth applications within Azure AD (rules).
*   Investigate any detected consent events, focusing on applications with unusual or overly broad permission requests.
*   Review and strengthen user awareness training to educate users about the risks of granting consent to untrusted applications.
*   Implement policies to restrict user consent capabilities and require administrator approval for certain applications or permission types (references).
*   Monitor Azure AD audit logs for suspicious activity related to OAuth application registrations and consent grants (data_source).
*   Regularly review existing OAuth application permissions to identify and revoke any unnecessary or risky grants.
