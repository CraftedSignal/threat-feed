---
title: Entra ID OAuth Application Redirect URI Modified
slug: 2026-06-entra-id-oauth-redirect-uri
description: Adversaries are modifying OAuth application redirect URIs (ReplyUrls) in Microsoft Entra ID to intercept OAuth authorization codes and steal tokens, granting unauthorized access without new application registration or user consent.
date: "2026-06-18T15:41:56Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - identity
  - azure
  - persistence
  - credential-access
  - token-theft
  - microsoft-entra-id
vendors:
  - Microsoft
products:
  - Entra ID
  - Azure AuditLogs
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
references:
  - https://learn.microsoft.com/en-us/entra/identity-platform/reply-url
  - https://www.microsoft.com/en-us/security/blog/2026/03/02/oauth-redirection-abuse-enables-phishing-malware-delivery/
rules:
  - title: Entra ID OAuth Application AppAddress Modified
    description: Detects modifications to OAuth application redirect URIs (ReplyUrls) in Entra ID by monitoring 'Update application' events where the 'AppAddress' property is altered, indicating a change to the application's redirect URIs.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1528
      - T1556
    data_sources:
      - cloud
      - azure
  - title: Entra ID OAuth Application ReplyUrls Changed (Excluding Localhost)
    description: Detects modifications to OAuth application redirect URIs (ReplyUrls) in Entra ID where a new, potentially external URI is added, excluding common localhost development URIs, indicating potential token theft preparation.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1528
      - T1556
    data_sources:
      - cloud
      - azure
rules_count: 2
---

This threat involves adversaries abusing legitimate Microsoft Entra ID (formerly Azure Active Directory) functionality to achieve persistence and credential access. Attackers modify existing, trusted OAuth 2.0 application registrations by adding an attacker-controlled redirect URI (ReplyUrl). This subtle change allows the interception of OAuth authorization codes when legitimate users authenticate to the compromised application. Unlike registering a new application or requiring explicit user consent, modifying an existing application's redirect URI can go unnoticed, maintaining all prior user consents. This technique enables token theft, granting attackers unauthorized access to resources such as Mail, Files, or directory scopes associated with the affected application, posing a significant risk to an organization's identity infrastructure. The technique is detailed in Microsoft's guidance on OAuth redirection abuse.

## Attack Chain

1.  **Initial Access / Reconnaissance**: Attacker gains access to an Entra ID tenant with permissions to modify application registrations (e.g., via compromised credentials of an administrator or application owner).
2.  **Application Identification**: Attacker identifies a high-value, trusted OAuth 2.0 application registration within Entra ID that has existing user consents and valuable permissions (e.g., Mail.Read, Files.ReadWrite, Directory.Read.All).
3.  **Redirect URI Modification**: Attacker modifies the identified application's `ReplyUrls` property, adding an attacker-controlled domain or endpoint as a valid redirect URI. This modification is logged as an "Update application" event in Azure Audit Logs.
4.  **Token Interception Setup**: The attacker sets up a web server at the newly added redirect URI to act as an OAuth authorization endpoint, designed to capture authorization codes or tokens redirected by Entra ID.
5.  **User Authentication Trigger**: Legitimate users attempt to access the compromised application, initiating the standard OAuth 2.0 authorization flow.
6.  **Authorization Code Redirection**: Entra ID, following the legitimate OAuth flow, redirects the user's browser (along with the authorization code) to one of the registered `ReplyUrls`, which now includes the attacker's controlled URI.
7.  **Token Theft**: The attacker's endpoint intercepts the authorization code. The attacker then exchanges this code for an access token and potentially a refresh token, gaining unauthorized access to the user's resources via the compromised application's permissions.
8.  **Post-Exploitation**: Attacker uses the stolen tokens to access data, execute actions, or maintain persistence within the target environment (e.g., read emails, exfiltrate files, escalate privileges).

## Impact

The impact of successful OAuth redirect URI modification and subsequent token theft can be severe. Attackers gain unauthorized access to an organization's cloud resources, including sensitive data within mailboxes, files, and directory services, depending on the permissions granted to the compromised application. This technique bypasses traditional multi-factor authentication (MFA) protections as it relies on token interception after a legitimate authentication event. The breach can lead to data exfiltration, business email compromise (BEC), and further privilege escalation within the Azure/Microsoft 365 environment, potentially affecting all users of the targeted application. Since this attack leverages trusted applications, it's often difficult for end-users to identify.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM to detect "Update application" events targeting `AppAddress` properties or modifications to `ReplyUrls` in Entra ID.
*   Investigate all `Update application` events in Entra ID Audit Logs, specifically reviewing `azure.auditlogs.properties.initiated_by` to identify the actor and `target_resources.modified_properties` to check changes to `ReplyUrls`.
*   Establish strict change management processes for application registrations in Entra ID, especially for those with high-privilege Graph API permissions, referencing the `references` section for best practices.
*   Regularly review the `ReplyUrls` of critical applications for any unauthorized or suspicious entries, and specifically geolocate and WHOIS the domains of newly added URIs as recommended in the rule description.
