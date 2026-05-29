---
title: M365 Exchange Inbox Forwarding Rule Created
slug: 2026-05-m365-exchange-inbox-rule
description: This rule detects the creation of new inbox forwarding rules in Microsoft 365, which can be abused by attackers to intercept and exfiltrate email data to external addresses.
date: "2026-05-29T13:29:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - saas
  - email
  - microsoft_365
  - configuration_audit
  - email_collection
vendors:
  - Microsoft
products:
  - Microsoft 365
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
references:
  - https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/responding-to-a-compromised-email-account?view=o365-worldwide
  - https://docs.microsoft.com/en-us/powershell/module/exchange/new-inboxrule?view=exchange-ps
  - https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-outlook-rules-forms-attack?view=o365-worldwide
  - https://raw.githubusercontent.com/PwC-IR/Business-Email-Compromise-Guide/main/Extractor%20Cheat%20Sheet.pdf
  - https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/
rules:
  - title: Detect M365 Exchange Inbox Rule Created to External Domain
    description: Detects the creation of a new inbox rule in Microsoft 365 Exchange that forwards emails to an external domain.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1114.003
    data_sources:
      - webserver
  - title: Detect M365 Exchange PowerShell Cmdlets Used for Inbox Rule Modification
    description: Detects the use of specific PowerShell cmdlets associated with the creation or modification of Exchange Inbox rules.
    platform: sigma
    severity: low
    tactics:
      - collection
    techniques:
      - T1114.003
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers can abuse Microsoft 365 Exchange inbox rules to intercept and exfiltrate email data without making organization-wide configuration changes or having the corresponding privileges. This involves creating or modifying inbox rules to forward emails to externally controlled accounts. The detection rule focuses on successful events that specify forwarding parameters, thus identifying potential unauthorized email redirection activities. This activity is particularly concerning as it allows attackers to maintain persistence and access sensitive information without direct compromise of user credentials, blending in with legitimate administrative functions. A recent AI-enabled device code phishing campaign in April 2026 further highlights the importance of monitoring Exchange configurations for malicious rule creation.

## Attack Chain

1. Initial Access: An attacker gains initial access to a user's M365 account, possibly through phishing or credential stuffing.
2. Privilege Escalation (if needed): The attacker may attempt to escalate privileges within the compromised account or lateral movement to an account with appropriate permissions.
3. Rule Creation/Modification: The attacker uses Exchange PowerShell cmdlets like `New-InboxRule`, `Set-InboxRule`, `Set-Mailbox`, `Set-TransportRule`, or `New-TransportRule` to create a new inbox rule or modify an existing one.
4. Forwarding Configuration: The attacker configures the inbox rule to forward emails based on specific conditions to an external email address they control, using parameters such as `ForwardTo`, `ForwardAsAttachmentTo`, or `RedirectTo`.
5. Data Collection: Emails that meet the defined conditions are automatically forwarded to the attacker's external email address.
6. Data Exfiltration: The attacker collects sensitive information from the forwarded emails.
7. Persistence: The inbox rule remains active, providing ongoing access to email data as it arrives in the user's mailbox.

## Impact

Successful exploitation can lead to the exfiltration of sensitive company information, including confidential documents, financial data, and customer information. This can result in financial loss, reputational damage, and legal liabilities. The number of victims and the extent of the damage depend on the scope of the compromised accounts and the sensitivity of the data being forwarded.

## Recommendation

*   Deploy the Sigma rule `Detect M365 Exchange Inbox Rule Created to External Domain` to your SIEM and tune for your environment to identify suspicious forwarding rules.
*   Review the Microsoft 365 audit logs for events related to `New-InboxRule`, `Set-InboxRule`, `Set-Mailbox`, `Set-TransportRule`, and `New-TransportRule` where the forwarding address is external to the organization, as outlined in the rule description.
*   Implement multi-factor authentication (MFA) for all user accounts to reduce the risk of initial access via compromised credentials.
*   Regularly review and update email security policies to prevent unauthorized forwarding rules, as mentioned in the references.
*   Enable Sysmon process-creation logging to improve detection of malicious PowerShell activity, and investigate related detections.
