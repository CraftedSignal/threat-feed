---
title: M365 Identity OAuth Illicit Consent Grant by Rare Client and User
slug: 2024-01-m365-oauth-consent
description: Adversaries may register a malicious application in Microsoft Entra ID and trick users into granting excessive permissions via OAuth consent, allowing the malicious application to access resources in Microsoft 365 on behalf of the user, potentially leading to data exfiltration.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - o365
  - oauth
  - consent-grant
  - phishing
  - initial-access
vendors:
  - Microsoft
products:
  - Microsoft 365
  - Azure Active Directory
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://www.wiz.io/blog/midnight-blizzard-microsoft-breach-analysis-and-best-practices
  - https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants?view=o365-worldwide
  - https://www.cloud-architekt.net/detection-and-mitigation-consent-grant-attacks-azuread/
  - https://docs.microsoft.com/en-us/defender-cloud-apps/investigate-risky-oauth#how-to-detect-risky-oauth-apps
  - https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
rules:
  - title: Detect New M365 OAuth Consent Grant
    description: Detects successful consent grants to applications in Microsoft 365, indicating potential illicit consent grant attacks.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.002
    data_sources:
      - webserver
      - o365
  - title: Detect Rare Client and User OAuth Consent
    description: Detects a new consent grant to an application using Microsoft 365 audit logs based on the user and client ID have not been seen doing this activity in the last 14 days.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.002
    data_sources:
      - webserver
      - o365
rules_count: 2
---

This threat brief focuses on the detection of illicit consent grant attacks within Microsoft 365 environments. These attacks involve adversaries creating and registering malicious applications within Azure Active Directory (Azure AD), now known as Microsoft Entra ID. The attackers then trick users into granting consent to these applications, thereby granting the application permissions to access resources within Microsoft 365, such as mail, profiles, and files. This is typically accomplished through spearphishing campaigns that direct users to a pre-crafted OAuth consent URL. The Elastic detection rule "M365 Identity OAuth Illicit Consent Grant by Rare Client and User" is designed to identify such consent grants by focusing on newly observed combinations of users and client IDs, thus highlighting potentially malicious activity. This activity started being tracked around 2025/03/24, defenders should prioritize detection and remediation of these attacks due to the potential for data exfiltration and account compromise.

## Attack Chain

1.  **Application Registration:** The attacker registers a malicious application within Azure AD (Entra ID). This involves creating an application object and defining the permissions it requires.
2.  **Crafting the Phishing URL:** The attacker crafts a spearphishing email containing a malicious OAuth consent URL. This URL is designed to appear legitimate and entice the user to grant consent.
3.  **Spearphishing Campaign:** The attacker sends the spearphishing email to targeted users within the organization.
4.  **User Grants Consent:** The user, believing the request is legitimate, clicks the link and grants consent to the application. This establishes an OAuth grant.
5.  **Application Accesses Resources:** The malicious application leverages the granted consent to access resources within Microsoft 365 on behalf of the user, such as mail, files, and profiles.
6.  **Data Exfiltration:** The application exfiltrates sensitive data from the compromised accounts. This data can be used for further attacks or sold on the black market.
7.  **Maintaining Persistence:** The attacker may use the compromised accounts to maintain persistence within the environment.
8.  **Lateral Movement:** Using the initial foothold, the attacker moves laterally to other systems or accounts within the organization to gain broader access.

## Impact

A successful illicit consent grant attack can lead to widespread data exfiltration, impacting potentially thousands of users depending on the scope of the granted permissions. Targeted sectors include organizations that rely heavily on Microsoft 365 for daily operations, such as financial institutions, healthcare providers, and government agencies. The consequences can range from loss of sensitive data and intellectual property to regulatory fines and reputational damage. The Elastic rule assigns a risk score of 47 to this type of activity.

## Recommendation

*   Deploy the Sigma rule `Detect New M365 OAuth Consent Grant` to identify suspicious consent activity based on the "Consent to application." event action and successful outcome, tuning the threshold as needed to reduce false positives.
*   Review the Microsoft 365 audit logs as described in the rule description by searching for `event.dataset: "o365.audit"` and `event.action: "Consent to application."` to validate potential attacker controlled applications.
*   Enable the Admin consent workflow as outlined in the references to restrict user-granted consent and require administrator approval for high-risk application permissions.
*   Regularly audit existing applications in your environment and revoke consent for any suspicious or unnecessary applications, referencing the investigation steps included in the rule notes.
