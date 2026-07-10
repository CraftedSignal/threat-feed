---
title: Microsoft Graph API Request User Impersonation by Unusual Client
slug: 2024-01-graph-api-user-impersonation
description: Detection of the first-time use of a Microsoft Graph API request by a specific client application ID, user principal object ID, and tenant ID, potentially indicating unauthorized access via phishing, token theft, or OAuth abuse.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - cloud
  - azure
  - graphapi
  - initial_access
vendors:
  - Microsoft
products:
  - Microsoft Graph API
  - Microsoft 365
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
references:
  - https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
  - https://pushsecurity.com/blog/consentfix
rules:
  - title: Microsoft Graph API Request User Impersonation by Unusual Client App ID
    description: Detects the first-time use of a Microsoft Graph API request by a specific client application ID in combination with a user principal object ID and tenant ID, potentially indicating unauthorized access.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - network_connection
      - azure
  - title: Microsoft Graph API Request with Client Authentication Method 0
    description: Detects Graph API requests using client authentication method 0, which is indicative of user-delegated permissions, which might be abused by attackers.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - network_connection
      - azure
rules_count: 2
---

This detection identifies the initial use of a Microsoft Graph API request originating from a specific client application ID (`azure.graphactivitylogs.properties.app_id`) tied to a user principal object ID (`azure.graphactivitylogs.properties.user_principal_object_id`) and a tenant ID (`azure.tenant_id`). This activity may signify unauthorized access achieved through methods like phishing, stolen tokens, or exploitation of OAuth workflows. Threat actors may leverage legitimate Microsoft or third-party application IDs to evade suspicion while performing actions on behalf of compromised users. The rule focuses on identifying unusual combinations of these three identifiers within a defined timeframe to highlight potentially malicious activity that bypasses standard authentication alerts.

## Attack Chain

1.  The attacker compromises user credentials through phishing or other means (T1566).
2.  The attacker obtains or steals a legitimate application access token (T1528).
3.  The attacker uses the stolen access token to make authenticated requests to the Microsoft Graph API, impersonating the compromised user.
4.  The attacker queries the Graph API for sensitive information such as user details, email, or files.
5.  The attacker accesses and potentially downloads sensitive data through the Graph API.
6.  The attacker leverages the compromised account to perform actions such as sending emails or creating resources.
7.  The attacker maintains persistence by creating new OAuth applications or modifying existing ones.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data, including emails, files, and user information, within a Microsoft 365 environment. Attackers can leverage compromised accounts to perform malicious actions, such as sending phishing emails or creating new resources. The scope of impact depends on the permissions granted to the compromised application and the data accessible through the Graph API. Detecting the initial unusual use of a client ID helps in early identification before significant damage occurs.

## Recommendation

*   Deploy the Sigma rule "Microsoft Graph Request User Impersonation by Unusual Client" to your SIEM and tune the `history_window_start` parameter to your environment needs.
*   Review `azure.graphactivitylogs.properties.user_principal_object_id` and correlate with recent sign-in logs for the associated user as mentioned in the rule's note section.
*   Inspect `azure.graphactivitylogs.properties.scopes` to understand the level of access being requested by the app, as suggested in the rule's note section.
*   Implement Conditional Access policies to restrict Graph API access based on app type, IP address, or device state as described in the rule's note section.
*   Monitor usage of new or uncommon `app_id` values across your tenant.
