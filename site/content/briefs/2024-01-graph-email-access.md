---
title: Unusual Microsoft Graph Email Access via OAuth Application
slug: 2024-01-graph-email-access
description: An adversary might use a phished OAuth refresh token or Primary Refresh Token (PRT) with a first-party application to access email resources via Microsoft Graph API, particularly focusing on unusual application and user combinations.
date: "2024-01-03T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - graphapi
  - oauth
  - email
vendors:
  - Microsoft
products:
  - Microsoft Graph API
  - Microsoft 365
  - Microsoft Entra ID
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
  - https://github.com/dirkjanm/ROADtools
  - https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/
  - https://pushsecurity.com/blog/consentfix
rules:
  - title: Microsoft Graph Unusual App Email Access
    description: Detects access to email resources via Microsoft Graph API using a first-party application by an unusual user and application combination.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - defense_evasion
    techniques:
      - T1114.002
      - T1550.001
    data_sources:
      - webserver
      - linux
  - title: Suspicious Graph API Request to Email Resources
    description: Detects suspicious access to email resources via the Microsoft Graph API by monitoring for specific URL paths and scopes.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1114.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This detection identifies potentially malicious access to email resources through the Microsoft Graph API. Attackers may leverage compromised OAuth refresh tokens or Primary Refresh Tokens (PRTs) to access sensitive email data. The activity is characterized by requests to Microsoft Graph API endpoints such as `/me/mailFolders/inbox/messages` or `/users/{user_id}/messages`, using a public client application ID on behalf of a user. The rule focuses on identifying novel combinations of application ID and user principal object ID accessing email resources within a 14-day timeframe, as this may indicate a compromised or newly deployed malicious application. This behavior could be related to campaigns similar to those observed by Volexity targeting Microsoft 365 OAuth workflows.

## Attack Chain

1.  The attacker compromises a user's credentials or obtains a valid OAuth refresh token or PRT through phishing or other means (T1566).
2.  The attacker uses the compromised token to authenticate to the Microsoft Graph API via a custom or existing application.
3.  The application requests access to email-related scopes such as `Mail.Read`, `Mail.ReadWrite`, or `Mail.Send` (T1550.001).
4.  The application makes API calls to enumerate mail folders, read messages, or send emails on behalf of the compromised user (T1114.002).
5.  The attacker may exfiltrate sensitive email content or use the compromised account to send phishing emails to other users (TA0009).
6.  The unusual combination of application ID and user principal triggers a detection due to the novel access pattern.
7.  The attacker persists by continuing to use the stolen token for ongoing access to email resources.

## Impact

Successful exploitation can lead to unauthorized access to sensitive email data, potentially resulting in data breaches, financial loss, and reputational damage. The compromise of user accounts can also enable attackers to send phishing emails or conduct further malicious activities within the organization. If undetected, the attacker can maintain persistent access to email resources.

## Recommendation

*   Deploy the Sigma rule `Microsoft Graph Unusual App Email Access` to detect novel app/user combinations accessing email data via Graph API, using `logs-azure.graphactivitylogs-*` as the index.
*   Investigate applications flagged by the rule by pivoting to Azure Portal -> Enterprise Applications and searching by the `azure.graphactivitylogs.properties.app_id` to determine app details, publisher, and consent status.
*   Review and restrict risky OAuth permissions in Conditional Access and App Governance policies, as mentioned in the triage steps within the rule's description.
*   Monitor for suspicious automation tools in the `user_agent.original` field within the `logs-azure.graphactivitylogs-*` index to identify potential scripted access.
*   Revoke the application's consent in Azure AD and revoke user refresh tokens via Microsoft Entra or PowerShell if unauthorized access is suspected.
