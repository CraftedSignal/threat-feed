---
title: Detection of Unusual OAuth Application Access to SharePoint and OneDrive
slug: 2026-08-entra-oauth-abuse
description: This brief details a detection strategy for identifying potential OAuth phishing and illicit consent grants by monitoring for first-time application access to Microsoft 365 file storage.
date: "2026-08-25T18:44:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - identity
  - oauth
  - phishing
  - collection
vendors:
  - Microsoft
products:
  - SharePoint Online
  - OneDrive for Business
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Adversaries often use malicious OAuth applications or phishing techniques to gain consent from users.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213.002
    technique_name: Sharepoint
    evidence: Identifies when an application accesses SharePoint Online or OneDrive for Business for the first time.
    confidence_band: high
references:
  - https://www.volexity.com/blog/2025/04/22/phishing-for-codes-russian-threat-actors-target-microsoft-365-oauth-workflows/
  - https://www.microsoft.com/en-us/security/blog/2022/09/22/malicious-oauth-applications-used-to-compromise-email-servers-and-spread-spam/
  - https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-consent-requests
rules:
  - title: Detect First-Time SharePoint or OneDrive Access by Unusual Client
    description: Detects when an application accesses SharePoint Online or OneDrive for Business for the first time in the tenant, which may indicate an illicit OAuth consent grant.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1213.002
    data_sources:
      - webserver
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Identity Security
  immediate_actions:
    - action: Deploy the new-terms detection rule to monitor for unusual OAuth access.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific KQL for detection.
  mitigation_plan:
    - priority: short_term
      action: Review and prune high-privilege application consents.
      owner: Identity Security
      addresses: Illicit OAuth consent grants
      evidence: Microsoft Entra ID management guidance.
---

Adversaries increasingly leverage malicious OAuth applications to gain persistent, unauthorized access to organizational data without traditional credential theft. By tricking users into granting consent to seemingly benign or productivity-focused applications, threat actors secure OAuth tokens that permit access to Microsoft SharePoint Online and OneDrive for Business. This activity persists even if the user's password is changed or MFA is enforced. This detection targets the 'first-time' access signal, identifying new or anomalous application identifiers (AppIDs) appearing within a tenant's sign-in logs. Defenders must distinguish between legitimate third-party SaaS integrations and malicious applications used for data exfiltration or reconnaissance.

## Impact

Successful exploitation allows attackers to bypass MFA and bypass conditional access policies, leading to large-scale data exfiltration, unauthorized document discovery, and long-term persistence within a target environment. This technique is frequently utilized in organized phishing campaigns to automate the harvesting of sensitive intellectual property or business communications.

## Recommendation

- Implement the detection of new, unseen AppIDs interacting with SharePoint Online and OneDrive for Business to baseline and alert on anomalous consent grants.
- Review and prune high-privilege OAuth permissions such as 'Files.ReadWrite.All' or 'Sites.ReadWrite.All' that exceed organizational requirements.
- Strengthen Conditional Access policies to mandate admin consent for risky applications and block unverified publishers from accessing sensitive resources.
- Audit existing enterprise application consents to identify and revoke access for suspicious, unused, or unverified applications.
