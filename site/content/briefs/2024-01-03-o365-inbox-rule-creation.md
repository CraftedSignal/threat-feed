---
title: Detection of Malicious Office 365 Inbox Rule Creation
slug: 2024-01-03-o365-inbox-rule-creation
description: This brief outlines the detection of malicious Office 365 inbox rule creation, where attackers leverage 'New-InboxRule' and 'Set-InboxRule' operations to forward, delete, or obfuscate emails, potentially leading to data exfiltration or business email compromise.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - o365
  - inbox-rule
  - email
  - data-exfiltration
  - business-email-compromise
vendors:
  - Microsoft
products:
  - Office 365
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
references:
  - https://attack.mitre.org/techniques/T1114/
  - https://www.hhs.gov/sites/default/files/help-desk-social-engineering-sector-alert-tlpclear.pdf
  - https://intelligence.abnormalsecurity.com/attack-library/threat-actor-convincingly-impersonates-employee-requesting-direct-deposit-update-in-likely-ai-generated-attack
rules:
  - title: O365 Suspicious Inbox Rule Creation - Forwarding
    description: Detects the creation of new Office 365 inbox rules that forward emails to external domains.
    platform: sigma
    severity: high
    tactics:
      - collection
      - defense_evasion
    techniques:
      - T1114.003
    data_sources:
      - webserver
      - o365
  - title: O365 Suspicious Inbox Rule Creation - Deletion
    description: Detects the creation of new Office 365 inbox rules that delete emails.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1564.008
    data_sources:
      - webserver
      - o365
  - title: O365 Inbox Rule Creation from Unfamiliar Source IP
    description: Detects inbox rule creation events originating from IP addresses not commonly associated with the user.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1564.008
    data_sources:
      - webserver
      - o365
rules_count: 3
---

Attackers frequently abuse Office 365 inbox rules to surreptitiously forward sensitive emails to external accounts, delete evidence of their presence, or redirect communications for business email compromise (BEC) campaigns. This analytic focuses on identifying anomalous creations or modifications of inbox rules through the 'New-InboxRule' and 'Set-InboxRule' operations. This activity is logged within the Office 365 Management Activity API. The detection specifically looks for rules that enable forwarding ('ForwardTo', 'ForwardAsAttachmentTo', 'RedirectTo'), deletion ('DeleteMessage', 'SoftDeleteMessage'), or moving/copying ('MoveToFolder', 'CopyToFolder') actions, as these are commonly used in malicious campaigns. Defenders should prioritize investigating new inbox rules configured with these actions, especially when coupled with suspicious source IP addresses or unusual user behavior.

## Attack Chain

1.  **Initial Compromise:** The attacker gains access to a user's Office 365 account, potentially through phishing, credential stuffing, or other means.
2.  **Authentication:** The attacker authenticates to Office 365 using the compromised account, generating authentication logs.
3.  **Rule Creation/Modification:** The attacker uses the 'New-InboxRule' or 'Set-InboxRule' cmdlets via PowerShell or the Office 365 portal to create or modify an inbox rule.
4.  **Forwarding Rule Configuration:** The rule is configured to forward emails matching specific criteria (e.g., from specific senders, containing certain keywords) to an external email address controlled by the attacker using 'ForwardTo', 'ForwardAsAttachmentTo', or 'RedirectTo' parameters.
5.  **Deletion/Obfuscation Rule Configuration:** Alternatively, the attacker configures the rule to delete or move specific emails to prevent the legitimate user from noticing suspicious activity using 'DeleteMessage', 'SoftDeleteMessage', 'MoveToFolder', or 'CopyToFolder' parameters.
6.  **Data Exfiltration:** Emails matching the rule's criteria are automatically forwarded to the attacker's external account, enabling data exfiltration.
7.  **Covering Tracks:** The attacker may delete logs or modify other settings to further obscure their activity.
8.  **Continued Monitoring:** The attacker monitors the forwarded emails for valuable information, such as financial data, intellectual property, or sensitive communications, potentially leading to further attacks or extortion.

## Impact

Successful exploitation of Office 365 inbox rules can lead to significant data breaches, financial losses, and reputational damage. Attackers can exfiltrate sensitive information, intercept financial transactions, and compromise confidential communications. Business Email Compromise (BEC) attacks frequently leverage this technique. Depending on the compromised account's role, the scope of the impact can range from individual data theft to enterprise-wide breaches, potentially affecting thousands of users.

## Recommendation

*   Enable and monitor the Office 365 Management Activity API logs to capture 'New-InboxRule' and 'Set-InboxRule' events, as described in the overview section.
*   Deploy the Sigma rules provided in this brief to your SIEM and tune them for your specific Office 365 environment.
*   Investigate any alerts generated by these rules, paying close attention to the user account, source IP address ('src' field in the Sigma rules), and the parameters used in the inbox rule creation/modification, focusing on the 'Parameters{}.Name' field.
*   Implement multi-factor authentication (MFA) for all Office 365 accounts to mitigate the risk of account compromise, which is a prerequisite for this attack.
*   Educate users on the risks of phishing and other social engineering techniques to prevent initial account compromise.
*   Review and audit existing inbox rules regularly to identify any suspicious or unauthorized configurations.
