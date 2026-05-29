---
title: M365 Exchange Inbox Rule with Obfuscated Name
slug: 2026-05-m365-exchange-inbox-rule-obfuscated-name
description: This rule detects when a Microsoft Exchange inbox rule is created or modified with a name composed only of special characters, which adversaries may use to evade detection and hide malicious forwarding or deletion rules.
date: "2026-05-29T10:26:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - saas
  - email
  - microsoft 365
  - exchange
  - defense evasion
  - persistence
vendors:
  - Microsoft
products:
  - Microsoft 365
  - Exchange Server
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1137
    technique_name: Office Application Startup
references:
  - https://www.microsoft.com/en-us/security/blog/2026/04/06/ai-enabled-device-code-phishing-campaign-april-2026/
rules:
  - title: Detect M365 Exchange Inbox Rule with Obfuscated Name
    description: Detects when a Microsoft Exchange inbox rule is created or modified with a name composed only of special characters. Parses rule names from `o365.audit.ObjectId`.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1137.005
      - T1564.008
    data_sources:
      - o365
      - o365
  - title: Detect M365 Exchange Inbox Rule Forwarding to External Domain
    description: Detects when an Exchange inbox rule is created or modified to forward emails to an external domain.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1137.005
      - T1564.008
    data_sources:
      - o365
      - o365
rules_count: 2
---

This detection rule identifies when a Microsoft Exchange inbox rule is created or modified with a name consisting solely of special characters. The rule focuses on `New-InboxRule` and `Set-InboxRule` events, analyzing the `o365.audit.ObjectId` field, which encodes the mailbox identity and rule name. Attackers obfuscate rule names to evade detection, hide malicious forwarding or deletion rules, and blend in with benign audit noise. This activity can be indicative of a compromised account being used to exfiltrate data or redirect sensitive information. Defenders should investigate flagged events to determine the actor involved and any malicious actions associated with the obfuscated inbox rule, particularly checking forwarding and redirect parameters for external destinations. The activity was observed in April 2026 and leverages a combination of AI and device code phishing.

## Attack Chain

1. An attacker gains initial access to a user's Microsoft 365 account, potentially through phishing.
2. The attacker authenticates to Exchange Online using the compromised credentials.
3. The attacker executes either the `New-InboxRule` or `Set-InboxRule` cmdlet via PowerShell or the Exchange Management Shell.
4. The attacker crafts an inbox rule with a name consisting only of special characters (e.g., "!@#$%^").
5. The `o365.audit.ObjectId` field in the audit logs records the obfuscated inbox rule name.
6. The inbox rule is configured to forward emails to an external address, delete emails containing specific keywords, or move emails to a hidden folder.
7. The rule activates and begins to process incoming emails according to the attacker's configuration.
8. The attacker achieves their objective, such as exfiltrating sensitive information or covering their tracks by deleting evidence.

## Impact

A successful attack can lead to data exfiltration, where sensitive emails are forwarded to an attacker-controlled address. It can also lead to data loss if emails are deleted or moved to inaccessible folders. Organizations may face compliance violations, financial losses, and reputational damage as a result of compromised email accounts. The impact depends on the sensitivity of the information handled by the compromised account.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect the creation or modification of Exchange inbox rules with obfuscated names, focusing on the `o365.audit.ObjectId` field.
*   Review forwarding and redirect parameters (`ForwardTo`, `ForwardAsAttachmentTo`, `ForwardingAddress`, `RedirectTo`, `RedirectToRecipients`) for external destinations when a suspicious inbox rule is detected.
*   Monitor Entra ID sign-in logs for unusual login activity associated with users who created or modified suspicious inbox rules, correlating `o365.audit.UserId` with `source.ip`.
*   Inspect the `o365.audit.Parameters` for suspicious actions such as `DeleteMessage`, `MoveToFolder`, or `SubjectContainsWords` in flagged events.
*   Implement multi-factor authentication (MFA) to reduce the risk of account compromise.
