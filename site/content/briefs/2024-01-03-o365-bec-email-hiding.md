---
title: O365 BEC Email Hiding Rule Creation
slug: 2024-01-03-o365-bec-email-hiding
description: This analytic detects suspicious Office 365 mailbox rule creation, a common technique used in Business Email Compromise (BEC), by scoring rule attributes like short names, marking emails as read, and moving emails to specific folders.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - bec
  - office365
  - email
vendors:
  - Microsoft
products:
  - Office 365
  - Exchange
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1564
    technique_name: Hide Artifacts
references:
  - https://attack.mitre.org/techniques/T1564/008/
  - https://github.com/splunk/security_content/blob/main/detections/cloud/o365_bec_email_hiding_rule_created.yml
rules:
  - title: O365 BEC Email Hiding Rule Created
    description: Detects suspicious Office 365 mailbox rule creation indicative of BEC activity based on short/unusual rule names and actions.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1564.008
    data_sources:
      - cloud
      - o365
  - title: O365 BEC MarkAsRead Inbox Rule
    description: Detects Office 365 inbox rules that automatically mark emails as read, a common technique used to hide malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1564.008
    data_sources:
      - cloud
      - o365
rules_count: 2
---

This threat brief focuses on detecting malicious mailbox rule creation within Office 365 environments, a tactic frequently employed in Business Email Compromise (BEC) attacks. Attackers, after gaining unauthorized access to a user's account, create inbox rules to hide or redirect sensitive emails, enabling them to conduct fraudulent activities undetected. This activity is often performed through `New-InboxRule` or `Set-InboxRule` operations. The detection strategy involves analyzing mailbox rule attributes such as short or unusual rule names, automated marking of emails as read, and moving emails to specific folders (e.g., RSS, Archive). A scoring mechanism is applied to identify combinations of these attributes indicative of malicious intent. Detecting these rules early can prevent financial loss and reputational damage.

## Attack Chain

1. **Initial Access:** Attacker gains unauthorized access to an Office 365 account, possibly through phishing, credential stuffing, or other methods.
2. **Privilege Escalation (If Needed):** The attacker may attempt to escalate privileges within the compromised account to gain further control.
3. **Rule Enumeration (Optional):** The attacker may enumerate existing inbox rules using commands to understand the current configuration.
4. **Malicious Rule Creation/Modification:** The attacker creates a new inbox rule or modifies an existing one using `New-InboxRule` or `Set-InboxRule` operations within Exchange. This rule is designed to hide or redirect emails.
5. **Rule Configuration:** The attacker configures the rule to automatically mark emails as read (`MarkAsRead="True"`), move them to specific folders like "RSS", "Conversation History", or "Archive" (`MoveToFolder`), or forward them to an external address. The rule name is often short and/or nonsensical.
6. **Email Hiding/Redirection:** The rule is activated, and incoming emails matching the rule's criteria are automatically hidden, moved, or redirected, preventing the legitimate user from seeing them.
7. **Data Exfiltration/Fraudulent Activity:** The attacker monitors the redirected emails for sensitive information or uses the compromised account to send fraudulent emails, initiate fraudulent transactions, or perform other malicious activities.

## Impact

Successful execution of this attack can lead to significant financial losses, data breaches, and reputational damage. Attackers can use hidden or redirected emails to gather sensitive information, conduct phishing campaigns against internal and external contacts, and initiate fraudulent wire transfers. The number of victims and the scale of the damage depend on the attacker's objectives and the duration of the compromise.

## Recommendation

*   Install the Splunk Microsoft Office 365 Add-on and ingest Office 365 management activity events to provide the necessary logs for detection.
*   Install the Splunk TA URL Toolbox (https://splunkbase.splunk.com/app/2734/) to enable entropy calculation for rule names.
*   Deploy the provided Sigma rule `O365 BEC Email Hiding Rule Created` to your SIEM and tune the `entropy_score` and `len_score` thresholds based on your environment to reduce false positives.
*   Monitor Office 365 management activity logs for `New-InboxRule` and `Set-InboxRule` operations, focusing on rules with suspicious attributes.
