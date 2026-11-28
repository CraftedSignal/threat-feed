---
brief_id: brief-2026-11-28-o365-admin-mail-access
event_id: brief-2026-11-28-o365-admin-mail-access
revision: 1
activity_at: "2026-11-28T20:52:34Z"
title: 'Microsoft 365: Detection of privileged email access via security features'
slug: 2026-11-o365-admin-mail-access
description: This detection monitors for the use of Microsoft 365 Security & Compliance Center premium investigation features, such as Threat Explorer, to directly view user email.
date: "2026-11-28T20:52:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
products:
  - Microsoft 365
affected_os:
  - cloud
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114.002
    technique_name: Remote Email Collection
    evidence: Adversaries may exploit privileged access with this premium feature to enumerate or exfiltrate sensitive data.
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Adversaries may exploit privileged access with this premium feature to enumerate or exfiltrate sensitive data.
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/o365_email_access_by_security_administrator.yml
  - https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/threat-explorer-investigate-delivered-malicious-email?view=o365-worldwide
action_plan:
  hunt_leads:
    - lead: Identify users leveraging the 'AdminMailAccess' operation within the Security & Compliance Center to directly view email content via Threat Explorer. Group results by the security administrator (src_user) and the target mailbox (user) to establish a baseline of privileged access and identify anomalous patterns of bulk email access.
      technique_id: T1114.002
      data_needed:
        - Office 365 Universal Audit Log
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Adversaries may exploit privileged access with this premium feature to enumerate or exfiltrate sensitive data.
    - lead: Investigate administrative accounts showing high volumes of 'AdminMailAccess' activity, which may indicate systematic enumeration or exfiltration of sensitive email data via premium investigative tools.
      technique_id: T1567
      data_needed:
        - Office 365 Universal Audit Log
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Adversaries may exploit privileged access with this premium feature to enumerate or exfiltrate sensitive data.
---

## Overview

The detection identifies when a user with sufficient access to the Microsoft 365 Security & Compliance portal uses premium investigation features, specifically Threat Explorer, to directly view email content. Adversaries may exploit privileged access with this feature to enumerate or exfiltrate sensitive data.

## Attack Chain

Adversaries with compromised or unauthorized high-privilege access utilize the "AdminMailAccess" operation within the Security & Compliance Center. This action allows direct visibility into user mailboxes.

## Impact

Direct access to email content can lead to the unauthorized collection and potential exfiltration of sensitive information.

## Recommendation

Install the Splunk Microsoft Office 365 Add-on and ingest Office 365 management activity events. Note that Threat Explorer is a premium feature, and logging availability depends on your license.
