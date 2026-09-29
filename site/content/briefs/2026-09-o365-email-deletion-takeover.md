---
title: Detection of O365 Email Receive and Hard Delete Takeover Behavior
slug: 2026-09-o365-email-deletion-takeover
description: Threat actors are suppressing evidence of account compromise by receiving and then hard-deleting emails related to sensitive banking, payroll, or credential changes within Office 365 environments.
date: "2026-09-29T10:11:25Z"
lastmod: "2026-09-29T10:11:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - o365
  - account-takeover
  - payroll-fraud
  - exfiltration
  - email-security
vendors:
  - Microsoft
products:
  - Office 365
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114.001
    technique_name: Local Email Collection
    evidence: The analytic identifies when an O365 email recipient receives and then deletes emails related to password or banking/payroll changes.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070.008
    technique_name: 'Indicator Removal: Email Deletion'
    evidence: The threat actor is suppressing evidence of phishing or unauthorized payroll changes.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: The attacker is attempting to redirect the victims payroll to an attacker controlled bank account.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1114
    technique_name: Email Collection
    evidence: Threat actors may attempt to transfer data through email as a simple means of exfiltration from the compromised mailbox.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1070.008
    technique_name: Indicator Removal on Host
    evidence: The detection is part of the Office 365 Account Takeover and Suspicious Emails stories.
    confidence_band: med
references:
  - https://attack.mitre.org/techniques/T1114/
  - https://www.hhs.gov/sites/default/files/help-desk-social-engineering-sector-alert-tlpclear.pdf
  - https://intelligence.abnormalsecurity.com/attack-library/threat-actor-convincingly-impersonates-employee-requesting-direct-deposit-update-in-likely-ai-generated-attack
  - https://github.com/splunk/security_content/blob/main/detections/cloud/o365_email_send_and_hard_delete_exfiltration_behavior.yml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable Office 365 Universal Audit Log ingestion for all Exchange mailbox activity.
      owner: SOC
      due: 24h
      evidence: How to implement section in source
  hunt_leads:
    - lead: Search for 'HardDelete' operations in the 'Recoverable Items' folder targeting users with recent sensitive emails.
      technique_id: T1070.008
      data_needed:
        - Office 365 Universal Audit Log
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source search query structure.
updates:
  - at: "2026-09-29T10:11:37Z"
    level: L1
    summary: added coverage for Office 365
    sources:
      - splunk-escu
    source_urls:
      - https://github.com/splunk/security_content/blob/main/detections/cloud/o365_email_send_attachments_excessive_volume.yml
---

This threat involves the unauthorized manipulation of Microsoft Office 365 mailboxes by threat actors to facilitate financial fraud or maintain persistence. After gaining access to a user account, adversaries target sensitive incoming communications such as banking notifications, direct deposit updates, MFA requests, or password reset alerts. To avoid detection by the account owner, the actor performs a hard delete of these messages from the 'Sent Items' or 'Recoverable Items' folders. This behavior is a critical indicator of account takeover (ATO) and is often associated with payroll redirection scams. Defenders should monitor for the correlation between incoming messages containing sensitive keywords and subsequent mailbox management activities that bypass standard trash bin recovery paths.

## Attack Chain

1. Attacker gains initial access to a user account (e.g., via phishing, session token theft, or credential stuffing).
2. Attacker configures mailbox access to monitor for sensitive communications.
3. Attacker intercepts or triggers an email related to payroll, MFA, or account recovery keywords.
4. Attacker performs the malicious action (e.g., redirects direct deposit or modifies security settings).
5. Attacker locates the confirmation or notification email within the inbox.
6. Attacker initiates an Exchange 'HardDelete' operation to remove the email from the 'Recoverable Items' or 'Sent Items' folders.
7. Attacker successfully obscures evidence of the unauthorized change, delaying victim detection.

## Impact

Successful exploitation allows threat actors to perform unauthorized financial transactions, such as redirecting payroll payments to attacker-controlled accounts. The act of hard-deleting messages removes forensic evidence of the compromise, complicating incident response and recovery efforts.

## Recommendation

Prioritize monitoring for anomalous mailbox operations that attempt to purge sensitive audit trails.
- Implement logging for 'HardDelete' operations in the Office 365 Universal Audit Log to detect potential evidence tampering.
- Correlate message trace data with mailbox management activity logs to identify the rapid succession of message receipt and deletion.
- Investigate user accounts flagged by these patterns for signs of unauthorized access, such as unexpected IP addresses or unusual User-Agent strings.
