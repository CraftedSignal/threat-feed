---
title: Microsoft 365 SharePoint Site Administrator Added
slug: 2024-01-sharepoint-privilege-escalation
description: Detection of a new SharePoint Site Administrator added in Microsoft 365, which adversaries may leverage after compromising a privileged account to maintain persistent, high-privilege access, as seen in the 0mega ransomware campaign.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - persistence
  - cloud
vendors:
  - Microsoft
products:
  - Microsoft 365
  - SharePoint
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://learn.microsoft.com/en-us/purview/audit-log-activities#site-permissions-activities
  - https://www.obsidiansecurity.com/blog/saas-ransomware-observed-sharepoint-microsoft-365/
rules:
  - title: M365 SharePoint Site Administrator Added
    description: Detects when a new SharePoint Site Administrator is added in Microsoft 365. This may indicate privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - web
      - o365
  - title: M365 SharePoint Site Admin Added - Modified Properties
    description: Detects when a new SharePoint Site Administrator is added by monitoring the modified properties for SiteAdmin changes.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1098.003
    data_sources:
      - web
      - o365
rules_count: 2
---

This rule detects the addition of a new SharePoint Site Administrator within Microsoft 365 environments. Site Administrators possess extensive control over SharePoint sites, including managing permissions, accessing content, and modifying settings. Attackers who have compromised a privileged account might add themselves or a controlled account as a Site Administrator. This allows them to maintain persistent, elevated access to sensitive data within SharePoint. This activity was observed during the 0mega ransomware campaign where threat actors escalated privileges to facilitate data exfiltration and deploy ransom notes across SharePoint sites. Detecting this activity is crucial to identify and prevent unauthorized access and potential data breaches within Microsoft 365 environments.

## Attack Chain

1.  The attacker compromises a privileged user account within the Microsoft 365 environment.
2.  The attacker authenticates to the Microsoft 365 environment using the compromised credentials.
3.  The attacker navigates to the SharePoint admin center.
4.  The attacker identifies a target SharePoint site to escalate privileges on.
5.  The attacker adds a new user (themselves or a controlled account) as a Site Collection Administrator for the target SharePoint site. This generates a `SiteCollectionAdminAdded` audit event.
6.  The attacker leverages the newly acquired Site Administrator privileges to access sensitive data stored on the SharePoint site.
7.  The attacker may modify site settings to further entrench their persistence.
8.  The attacker exfiltrates sensitive data or deploys ransomware across the SharePoint site.

## Impact

Successful exploitation can lead to unauthorized access to sensitive data stored within SharePoint sites, potential data breaches, and the deployment of ransomware. The 0mega ransomware campaign demonstrated the potential for significant disruption and financial losses stemming from this type of privilege escalation. Depending on the sensitivity of the data stored within the affected SharePoint sites, organizations may face regulatory fines, reputational damage, and legal liabilities.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect `SiteCollectionAdminAdded` events in your Microsoft 365 audit logs.
*   Review the `user.id`, `o365.audit.ModifiedProperties.SiteAdmin.NewValue`, and `o365.audit.SiteUrl` fields in the logs to identify the actor, the added admin, and the affected site as outlined in the rule's "Triage and Analysis" section.
*   Implement Privileged Access Management (PAM) or Privileged Identity Management (PIM) to require just-in-time elevation for SharePoint admin roles.
*   Enable multi-factor authentication (MFA) for all accounts with SharePoint administrative privileges as described in the "Response and Remediation" section.
