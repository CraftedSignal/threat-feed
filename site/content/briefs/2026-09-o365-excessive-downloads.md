---
title: Detection of Unauthorized OneDrive and SharePoint Mass Data Downloads
slug: 2026-09-o365-excessive-downloads
description: Adversaries are leveraging OAuth-based Device Code Authentication phishing to hijack user sessions and exfiltrate large volumes of files from Microsoft 365 cloud storage.
date: "2026-09-09T18:45:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - o365
  - cloud-security
  - exfiltration
  - oauth
vendors:
  - Microsoft
products:
  - OneDrive
  - SharePoint
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: This rule detects an excessive number of files downloaded from OneDrive using OAuth authentication.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Automated Exfiltration
    evidence: This may indicate a potential data exfiltration event, especially if the downloads are performed using OAuth authentication.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Threat actors may use OAuth phishing attacks to obtain valid access tokens and perform unauthorized data exfiltration.
    confidence_band: high
references:
  - https://www.volexity.com/blog/2025/02/13/multiple-russian-threat-actors-targeting-microsoft-device-code-authentication/
  - https://cloud.google.com/blog/topics/threat-intelligence/expansion-shinyhunters-saas-data-theft
action_plan:
  priority: elevated
  owners:
    - SOC
    - IAM Team
  immediate_actions:
    - action: Review and revoke suspicious OAuth application grants identified in M365 logs.
      owner: IAM Team
      due: 24h
      evidence: Unauthorized OAuth application usage is a primary indicator of this attack.
  hunt_leads:
    - lead: Identify users with high volumes of file downloads from OneDrive/SharePoint via OAuth tokens.
      technique_id: T1530
      data_needed:
        - M365 Audit Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: ESQL rule logic identifies count_distinct(file.name) >= 25 in 3-minute windows.
  mitigation_plan:
    - priority: immediate
      action: Enable Conditional Access policies requiring managed devices for OAuth application authentication.
      owner: IT Operations
      addresses: OAuth phishing persistence
      evidence: Restricting authentication to trusted devices limits session hijacking impact.
---

Threat actors are increasingly utilizing OAuth phishing techniques, specifically Device Code Authentication phishing, to compromise user sessions within Microsoft 365 environments. By successfully convincing a user to authorize a malicious OAuth application via device code flow, adversaries gain persistent and valid access tokens. These tokens are subsequently leveraged to perform mass, automated downloads of files from OneDrive for Business and SharePoint Online. 

This activity bypasses traditional password-based authentication and MFA, as the attacker effectively becomes the authenticated user within the cloud session. Detection requires identifying anomalous, high-volume file download patterns that deviate from standard enterprise behavior, specifically focusing on sessions established via third-party or unauthorized OAuth application IDs.

## Attack Chain

1. Attacker sends a spearphishing email or message prompting the victim to authenticate via a malicious OAuth application using Device Code flow.
2. Victim navigates to the Microsoft device login page and enters the code provided by the attacker-controlled application.
3. Victim authorizes the application, granting the attacker a persistent OAuth access token with Graph API or OneDrive/SharePoint permissions.
4. Attacker uses the stolen access token to authenticate against the Microsoft Graph API or OneDrive/SharePoint endpoints.
5. Attacker enumerates file paths and directory structures within the victim's OneDrive or SharePoint site to identify sensitive data.
6. Attacker initiates automated, high-volume file downloads (typically >25 unique files in a short time window) to exfiltrate data.
7. Data is transferred to attacker-controlled infrastructure over legitimate web service protocols.

## Impact

Successful exfiltration results in the compromise of sensitive corporate data stored in cloud repositories. The use of OAuth tokens allows for stealthy persistence and the potential for lateral movement within the M365 environment, potentially leading to further account takeovers or the compromise of additional cloud-resident data.

## Recommendation

- Deploy the provided ESQL detection rule to identify users or applications performing mass file downloads from OneDrive/SharePoint.
- Review Entra ID sign-in logs for sessions established using the `deviceCode` protocol that correlate with high-volume download activity.
- Audit existing OAuth application consents and revoke permissions for any unauthorized or unnecessary third-party applications.
- Enforce Conditional Access policies to restrict OAuth authentication to trusted devices and known enterprise applications.
- Educate users on the risks of Device Code Authentication phishing and promote the use of Microsoft Defender for Office 365 Safe Links.
