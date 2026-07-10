---
title: Entra ID OAuth User Impersonation to Microsoft Graph
slug: 2024-01-entra-oauth-impersonation
description: Detects potential session hijacking or token replay in Microsoft Entra ID, where a user signs in and subsequently accesses Microsoft Graph from a different IP address using the same session ID, indicating a successful OAuth phishing attack, session hijacking, or token replay attack.
date: "2024-01-03T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - entra_id
  - oauth
  - graph_api
  - token_replay
  - session_hijacking
  - initial_access
  - defense_evasion
vendors:
  - Microsoft
products:
  - Microsoft Entra ID
  - Microsoft Graph
  - Microsoft 365
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
  - https://github.com/dirkjanm/ROADtools
  - https://attack.mitre.org/techniques/T1078/004/
  - https://pushsecurity.com/blog/consentfix
rules:
  - title: Entra ID OAuth User Impersonation to Microsoft Graph
    description: Detects potential OAuth token replay or session hijacking by identifying Graph API access from a different IP address than the initial Entra ID sign-in for the same session.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - network_connection
      - azure
  - title: Suspicious Microsoft Graph API Permissions Scopes
    description: Detects suspicious Microsoft Graph API permission scopes being requested, possibly indicating malicious OAuth application consent.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This detection identifies potential session hijacking or token replay attacks targeting Microsoft Entra ID and Microsoft Graph. The rule focuses on scenarios where a user authenticates to Entra ID, and shortly after, Microsoft Graph is accessed using the same session ID but originating from a different IP address. This behavior can signify a successful OAuth phishing attack, session hijacking, or token replay attack where an attacker steals session cookies or refresh/access tokens to impersonate a legitimate user. The targeted resources are typically Microsoft 365 applications and data accessed via the Graph API. The rule leverages Microsoft Entra ID Sign-In Logs and Microsoft Graph Activity Logs to correlate sign-in events with Graph API access, excluding known benign application IDs to reduce false positives. It is based on research and observed techniques detailed in threat intelligence reports regarding OAuth phishing campaigns.

## Attack Chain

1.  The attacker sends a phishing email to a target user, enticing them to click a malicious link.
2.  The user is redirected to a fake OAuth consent page, controlled by the attacker, prompting them to grant permissions to a malicious application.
3.  The user unknowingly provides consent, granting the attacker access to their Entra ID resources.
4.  The attacker exchanges the authorization code for an access or refresh token.
5.  The attacker uses the stolen access token to make API calls to Microsoft Graph from a different IP address than the original sign-in.
6.  The attacker accesses sensitive data, such as emails, files, or contacts, via the Microsoft Graph API.
7.  The attacker may use ROADtools to enumerate permissions and access further resources.
8.  The attacker maintains persistence by using the refresh token to obtain new access tokens, even after the initial session expires.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data within Microsoft 365, including emails, files, contacts, and other resources accessible via the Microsoft Graph API. Attackers can use this access to perform data exfiltration, business email compromise (BEC), or further lateral movement within the organization. While the rule is designed to minimize false positives, legitimate scenarios like device switching and network roaming may trigger alerts, requiring careful investigation. If malicious activity is confirmed, affected user accounts must be immediately investigated and remediated to prevent further damage.

## Recommendation

*   Enable and configure the Microsoft Entra ID Sign-In Logs and Microsoft Graph Activity Logs integration to collect audit and activity logs via Azure Event Hub, as outlined in the rule setup instructions.
*   Deploy the provided Sigma rule `Entra ID OAuth User Impersonation to Microsoft Graph` to your SIEM and tune it for your environment, paying close attention to false positives related to device switching and network roaming.
*   Review and enforce conditional access policies, including multi-factor authentication and location-based access controls, to mitigate OAuth phishing attacks as mentioned in the triage section.
*   Revoke all refresh/access tokens for any user accounts flagged by this rule and reset their credentials, if malicious activity is confirmed.
*   Monitor network connections for the IPs detected by the Sigma rule and block them on the perimeter.
*   Review session control policies and conditional access enforcement as described in the investigation steps to prevent future token replay attacks.
