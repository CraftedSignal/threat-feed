---
brief_id: brief-2026-11-13-o365-inbox-rule-monitoring
event_id: brief-2026-11-13-o365-inbox-rule-monitoring
revision: 1
activity_at: "2026-11-13T21:09:36Z"
title: 'Microsoft Office 365: Detection of Inbox Rule Creation'
slug: 2026-11-o365-inbox-rule-monitoring
description: This analytic identifies the creation or modification of email inbox rules within Office 365 by monitoring for specific parameters that may indicate mail forwarding, removal, or obfuscation.
date: "2026-11-13T21:09:36Z"
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
tags:
  - o365
  - cloud-security
  - email-security
  - collection
  - persistence
  - defense-evasion
vendors:
  - Microsoft
products:
  - Office 365
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114.003
    technique_name: Email Forwarding Rule
    evidence: The analytic identifies the creation of new email inbox rules in an Office 365 environment, focusing on parameters that may indicate mail forwarding.
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1137.005
    technique_name: Outlook Rules
    evidence: Attackers also leverage this technique for multiple reasons including persistence.
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564.008
    technique_name: Email Hiding Rules
    evidence: It detects events... focusing on parameters that may indicate... removal, or obfuscation.
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/o365_email_new_inbox_rule_created.yml
  - https://attack.mitre.org/techniques/T1114/
  - https://attack.mitre.org/techniques/T1137/005/
  - https://www.hhs.gov/sites/default/files/help-desk-social-engineering-sector-alert-tlpclear.pdf
  - https://intelligence.abnormalsecurity.com/attack-library/threat-actor-convincingly-impersonates-employee-requesting-direct-deposit-update-in-likely-ai-generated-attack
rules:
  - title: O365 Email New Inbox Rule Created
    description: Identifies the creation of new email inbox rules in an Office 365 environment by detecting New-InboxRule and Set-InboxRule operations involving forwarding or deletion parameters.
    platform: sigma
    severity: medium
    data_sources:
      - cloud
      - Office 365 Universal Audit Log
rules_count: 1
---

Office 365 inbox rules are occasionally leveraged by attackers to perform collection, persistence, or defense evasion activities. While inbox rule creation is a typical end-user activity, this analytic identifies events logged under the New-InboxRule and Set-InboxRule operations that involve parameters such as ForwardTo, ForwardAsAttachmentTo, RedirectTo, SoftDeleteMessage, DeleteMessage, MoveToFolder, or CopyToFolder.

## Impact

Unauthorized inbox rule modifications allow for the automated forwarding, redirection, or deletion of incoming messages.

## Recommendation

Detection teams should ingest Office 365 management activity logs from the Universal Audit Log to monitor for these inbox rule operations and investigate rule configurations that deviate from expected user behavior.
