---
title: Entra ID Illicit Consent Grant via Registered Application
slug: 2024-01-03-entra-id-illicit-consent
description: Attackers register malicious applications within Entra ID and deceive users into granting extensive permissions through OAuth consent, enabling unauthorized access to sensitive data like emails and files.
date: "2024-01-03T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - entra-id
  - oauth
  - illicit-consent
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
references:
  - https://www.wiz.io/blog/midnight-blizzard-microsoft-breach-analysis-and-best-practices
  - https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants?view=o365-worldwide
  - https://www.cloud-architekt.net/detection-and-mitigation-consent-grant-attacks-azuread/
  - https://docs.microsoft.com/en-us/defender-cloud-apps/investigate-risky-oauth#how-to-detect-risky-oauth-apps
rules:
  - title: Detect Entra ID Illicit Consent Grant
    description: Detects consent grants to applications flagged as risky or newly seen within a short timeframe.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.002
    data_sources:
      - audit
      - azure
  - title: Detect Consent to Application Operation
    description: Detects consent operations in Azure audit logs
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - audit
      - azure
rules_count: 2
---

Attackers are increasingly leveraging illicit consent grants within Microsoft Entra ID to gain unauthorized access to sensitive data. This involves registering a malicious application within an organization's Entra ID environment and tricking users into granting it excessive permissions via OAuth consent. The attack commonly uses spearphishing to distribute links that lead users to grant permissions to seemingly legitimate applications. Once consent is granted, the attacker-controlled application can access resources like mail, profiles, and files on behalf of the compromised user. Detection focuses on identifying unusual consent activity within Azure audit logs, particularly new application consent grants and instances where Microsoft flags an application as risky. This activity is flagged using ES|QL aggregation logic over a 7-day window looking for new or risky user-application consent pairs.

## Attack Chain

1.  The attacker registers a malicious application within Microsoft Entra ID.
2.  The attacker crafts a spearphishing email containing a malicious link.
3.  The victim receives the spearphishing email and clicks the malicious link.
4.  The link redirects the victim to a consent page for the attacker's application.
5.  The consent page requests permissions to access resources such as mail, profiles, and files.
6.  The victim, believing the application is legitimate, grants consent.
7.  The attacker's application receives an OAuth access token.
8.  The attacker's application uses the access token to access resources on behalf of the compromised user, enabling data exfiltration or other malicious activities.

## Impact

A successful illicit consent grant attack can lead to unauthorized access to sensitive data, including emails, files, and user profiles. The impact includes data breaches, financial loss, and reputational damage. While the exact number of victims is unknown, this technique targets any organization using Microsoft Entra ID and relying on user consent for application access.

## Recommendation

*   Deploy the Sigma rule `Detect Entra ID Illicit Consent Grant` to your SIEM and tune for your environment to detect suspicious consent grants.
*   Review Azure audit logs for consent events where the `azure.auditlogs.properties.target_resources.0.modified_properties.5.new_value` field contains "*Risky application detected*".
*   Enable the Admin Consent Workflow in Azure AD to prevent unsanctioned user approvals.
*   Revoke the OAuth grant for any identified malicious application using Graph API or PowerShell.
