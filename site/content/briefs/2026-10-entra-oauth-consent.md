---
title: Entra ID End-User Consent to Malicious OAuth Applications
slug: 2026-10-entra-oauth-consent
description: Adversaries perform OAuth phishing by tricking users into granting malicious applications high-risk delegated scopes in Entra ID, enabling persistent, silent access to mail, files, and chat data via long-lived refresh tokens.
date: "2026-10-08T19:08:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - identity
  - azure
  - oauth
  - phishing
  - credential-access
vendors:
  - Microsoft
products:
  - Entra ID
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: Adversaries trick a user into granting OAuth consent to an application that requests delegated scopes giving access to mail, files, SharePoint, OneNote, contacts or Teams chats, typically together with 'offline_access'.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: Because 'offline_access' yields a long-lived refresh token, the application keeps access silently, without re-authentication or MFA.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-applications#end-user-consent
  - https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-app-consent
  - https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-app-consent-policies
  - https://learn.microsoft.com/en-us/defender-cloud-apps/investigate-risky-oauth
  - https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/
  - https://github.com/AlteredSecurity/365-Stealer
action_plan:
  priority: elevated
  owners:
    - SOC
    - IAM Team
  immediate_actions:
    - action: Review and audit high-risk OAuth consent grants in Entra ID using the provided logic.
      owner: SOC
      due: 48h
      evidence: Entra ID Audit Logs contain 'Consent to application' operations.
  mitigation_plan:
    - priority: immediate
      action: Enable the admin consent workflow for all users to prevent unauthorized end-user consent for sensitive scopes.
      owner: IAM Team
      addresses: OAuth App Consent TTP
      evidence: Microsoft security operations guidance.
---

Adversaries exploit the OAuth 2.0 authorization framework in Microsoft Entra ID to gain persistent access to sensitive cloud resources without requiring re-authentication or MFA. By crafting malicious applications and tricking users into granting delegated permissions, attackers obtain an access token and a long-lived 'offline_access' refresh token. This allows the attacker to maintain access even if the victim changes their password or updates their MFA configuration. 

The scope of targeting typically focuses on high-value delegated permissions related to Exchange Web Services (EWS), Microsoft Graph (mail, files, SharePoint, OneNote, Teams chats), and contacts. Because these applications are often registered as third-party, multi-tenant entities, they can be introduced into a target environment and provisioned upon the first user consent. Defenders must distinguish between sanctioned line-of-business applications and unsanctioned applications that may indicate the start of a business email compromise (BEC) or data exfiltration campaign.

## Attack Chain

1. Attacker registers a malicious application in an attacker-controlled Microsoft Entra tenant.
2. Attacker crafts a phishing campaign (e.g., via email or Teams) to lure a target user into a web interface.
3. The target user navigates to the malicious application's OAuth consent URL.
4. The malicious application requests a set of high-risk delegated permissions (e.g., Mail.ReadWrite, Files.ReadWrite.All).
5. The target user approves the request, triggering an Entra ID 'Consent to application' event where 'IsAdminConsent' is false.
6. The application receives an access token and a persistent 'offline_access' refresh token.
7. Attacker uses the refresh token to silently authenticate as the user, bypassing conditional access and MFA prompts.
8. Attacker performs exfiltration of mailbox items, files, or persistent monitoring of Teams communications to support BEC or lateral movement.

## Impact

Successful exploitation results in business email compromise (BEC), unauthorized access to sensitive file repositories (SharePoint/OneDrive), and potential exfiltration of proprietary communications. Attackers can maintain silent, durable access to the victim's account, allowing them to monitor ongoing conversations and impersonate the user without further interaction, leading to financial fraud or further credential harvesting.

## Recommendation

Prioritize the investigation of OAuth consent grants identified by the provided query, focusing on applications where 'Esql.app_owner_type' is 'external' and 'Esql.sp_provisioned_by_consent' is 'true'.
- Enable the Entra ID admin consent workflow to restrict end-user consent capabilities for sensitive application scopes.
- Revoke refresh tokens for applications found to be malicious via 'Remove-MgOauth2PermissionGrant'.
- Configure Conditional Access policies to enforce stricter requirements for application access based on publisher verification.
- Regularly audit third-party application permissions in the Enterprise Applications blade, specifically looking for applications with high-risk scopes and low user counts.
