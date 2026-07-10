---
title: Entra ID OAuth Phishing via First-Party Microsoft Application
slug: 2024-01-09-entra-id-oauth-phishing
description: Attackers are leveraging first-party Microsoft applications in Entra ID to conduct OAuth phishing attacks, bypassing traditional consent prompts and accessing sensitive resources like Microsoft Graph and legacy Azure AD.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - entra_id
  - oauth
  - phishing
  - initial_access
vendors:
  - Microsoft
products:
  - Entra ID
  - Microsoft Graph
  - Windows Azure Active Directory API
  - Microsoft 365
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
references:
  - https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-azure-monitor-sign-ins-log-schema
  - https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
  - https://pushsecurity.com/blog/consentfix
  - https://github.com/secureworks/family-of-client-ids-research
rules:
  - title: Entra ID OAuth Phishing via First-Party Microsoft Application - Developer Tools
    description: Detects potentially suspicious OAuth authorization activity where developer tools (Azure CLI, VSCode, PowerShell) access Microsoft Graph or legacy Azure AD resources.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078.004
      - T1566.002
    data_sources:
      - network_connection
      - azure
  - title: Entra ID OAuth Phishing via First-Party Microsoft Application - Legacy AAD
    description: Detects any FOCI application accessing the deprecated Windows Azure Active Directory resource.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078.004
      - T1566.002
    data_sources:
      - network_connection
      - azure
rules_count: 2
---

Attackers are exploiting the trust associated with first-party Microsoft applications within Entra ID to perform OAuth phishing campaigns, such as ConsentFix. These applications, belonging to the Family of Client IDs (FOCI), are pre-consented and cannot be blocked, making them ideal for bypassing consent prompts and gaining unauthorized access. The attackers phish users into granting these applications access to sensitive resources like Microsoft Graph or the deprecated Windows Azure Active Directory API. This access is then used to steal authorization codes and exchange them for tokens from attacker infrastructure. This activity was observed starting in early 2025 with ongoing campaigns in 2026.

## Attack Chain

1.  Attacker crafts a phishing email targeting a user, enticing them to click a malicious link.
2.  The link redirects the user to a legitimate Microsoft login page, pre-populated with a first-party Microsoft application (e.g., Azure CLI, Visual Studio Code, Azure PowerShell).
3.  The user is prompted to grant the application permissions to access resources like Microsoft Graph or Windows Azure Active Directory.
4.  The user grants consent, unknowingly providing the attacker with an authorization code.
5.  The attacker intercepts the authorization code and exchanges it for an access token using their own infrastructure.
6.  The attacker uses the stolen access token to access the user's data and resources via Microsoft Graph or Windows Azure Active Directory.
7.  The attacker may exfiltrate sensitive data, such as emails, files, or Teams messages.
8.  The attacker may also register devices or create new accounts for persistence.

## Impact

Successful OAuth phishing attacks can lead to unauthorized access to sensitive data, including emails, files, and other resources stored within Microsoft 365. Organizations may experience data breaches, financial losses, and reputational damage. The widespread nature of Microsoft 365 means that any organization relying on these services is potentially vulnerable. While the specific number of victims is not detailed, the references suggest widespread campaigns.

## Recommendation

*   Deploy the Sigma rule `Entra ID OAuth Phishing via First-Party Microsoft Application - Developer Tools` to detect suspicious sign-in activity involving developer tools accessing Microsoft Graph or legacy Azure AD (rule provided below).
*   Deploy the Sigma rule `Entra ID OAuth Phishing via First-Party Microsoft Application - Legacy AAD` to detect any FOCI application accessing the deprecated Windows Azure Active Directory resource (rule provided below).
*   Review `azure.signinlogs.properties.user_principal_name` and `source.ip` for geographic anomalies as detailed in the "Triage and analysis" section of the rule description.
*   Implement Conditional Access policies to restrict OAuth flows for these applications to compliant devices only.
*   Educate users about OAuth phishing and the risks of pasting authorization codes into websites.
