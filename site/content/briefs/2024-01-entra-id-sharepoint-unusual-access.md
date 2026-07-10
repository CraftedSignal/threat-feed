---
title: Entra ID Sharepoint or OneDrive Accessed by Unusual Client
slug: 2024-01-entra-id-sharepoint-unusual-access
description: An application accessing SharePoint Online or OneDrive for Business for the first time in a tenant could indicate OAuth phishing, illicit consent grants, or compromised third-party apps accessing file storage.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - azure
  - sharepoint
  - onedrive
  - oauth
  - phishing
  - illicit-consent
vendors:
  - Microsoft
products:
  - Entra ID
  - SharePoint Online
  - OneDrive for Business
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
  - https://www.microsoft.com/en-us/security/blog/2022/09/22/malicious-oauth-applications-used-to-compromise-email-servers-and-spread-spam/
  - https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-consent-requests
  - https://github.com/merill/microsoft-info/blob/main/_info/MicrosoftApps.json
rules:
  - title: Entra ID Sharepoint or OneDrive Accessed by Unusual Client
    description: Detects when an application accesses SharePoint Online or OneDrive for Business for the first time in the tenant.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - initial_access
    techniques:
      - T1213.002
      - T1566
    data_sources:
      - network_connection
      - azure
  - title: Entra ID Consent to Application Audit
    description: Detects consent to a new application in Entra ID via Audit Logs.
    platform: sigma
    severity: low
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1098.001
      - T1566
    data_sources:
      - network_connection
      - azure
rules_count: 2
---

This detection identifies when an application accesses SharePoint Online or OneDrive for Business for the first time within a tenant. This is a critical signal for detecting successful OAuth phishing campaigns, where users are tricked into granting consent to malicious applications. Once consent is granted, the malicious app can persistently access file storage without further user interaction. This also catches illicit consent grants, compromised third-party applications, or custom malicious apps registered by adversaries. The rule uses data from Entra ID sign-in logs to identify new application IDs accessing SharePoint or OneDrive resources. The rule looks back 9 months to establish a baseline of known applications.

## Attack Chain

1.  The attacker sends a phishing email with a link to a malicious OAuth application.
2.  The victim clicks the link and is redirected to a legitimate-looking consent page.
3.  The victim grants consent to the malicious application, unknowingly providing access to their data.
4.  The malicious application authenticates to Entra ID using the granted consent.
5.  The application accesses SharePoint Online or OneDrive for Business using the victim's permissions.
6.  The application exfiltrates sensitive data from SharePoint or OneDrive.
7.  The attacker uses the exfiltrated data for their objectives, such as financial gain or espionage.

## Impact

A successful OAuth phishing campaign or illicit consent grant can lead to significant data breaches. An attacker gaining access to SharePoint Online or OneDrive for Business can steal sensitive documents, intellectual property, and other confidential information. This can result in financial losses, reputational damage, and legal liabilities. There is no specific number of victims or sectors targeted detailed in the provided source material.

## Recommendation

*   Deploy the Sigma rule "Entra ID Sharepoint or OneDrive Accessed by Unusual Client" to your SIEM and tune for your environment to detect initial access of unusual applications.
*   Review `azure.signinlogs.properties.app_id` and `azure.signinlogs.properties.app_display_name` to identify the application and cross-reference with known legitimate applications, as described in the rule's Triage and Analysis section.
*   Monitor `azure.auditlogs` for recent `Consent to application` events matching suspicious app IDs to identify how consent was granted, as documented in the rule's analysis section.
*   Implement Conditional Access policies to require admin consent for high-risk permissions and block unverified publishers, as recommended in the Response and Remediation section.
*   Ensure that Microsoft Entra ID Sign-In Logs are being collected and streamed into the Elastic Stack via the Azure integration, as required by the rule setup.
