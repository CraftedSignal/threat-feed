---
title: Detection of Suspicious Inbox Manipulation Rules in Azure
slug: 2024-01-suspicious-inbox-rules
description: This brief focuses on detecting malicious inbox manipulation rules set within a user's Azure environment, often indicative of account compromise or insider threats aiming to conceal illicit activities.
date: "2024-01-02T14:30:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - attack.stealth
  - attack.t1140
vendors:
  - Microsoft
products:
  - Azure
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks#suspicious-inbox-manipulation-rules
  - https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins
rules:
  - title: Suspicious Inbox Manipulation Rules
    description: Detects suspicious rules that delete or move messages or folders are set on a user's inbox.
    platform: sigma
    severity: high
    tactics:
      - stealth
    techniques:
      - T1140
    data_sources:
      - azure
      - riskdetection
  - title: Suspicious Inbox Forwarding Rule Creation
    description: Detects the creation of inbox rules forwarding email to external domains.
    platform: sigma
    severity: medium
    tactics:
      - stealth
    techniques:
      - T1140
    data_sources:
      - azure
      - audit
rules_count: 2
---

Attackers can create inbox manipulation rules in cloud email environments like Microsoft 365 to hide their activity, exfiltrate data, or conduct further phishing attacks. These rules automatically delete, move, or forward emails based on sender, subject, or keywords. This can be used to hide evidence of a compromised account, or to intercept communications for Business Email Compromise (BEC). The `mcasSuspiciousInboxManipulationRules` risk event type in Azure Identity Protection flags such suspicious rules, allowing defenders to proactively identify and remediate compromised accounts. This detection focuses on unusual mailbox rule activity indicative of malicious intent, rather than legitimate business workflows.

## Attack Chain

1.  An attacker gains unauthorized access to a user's Azure account, potentially through credential theft or phishing (T1140).
2.  The attacker authenticates to the user's Microsoft 365 account.
3.  The attacker creates a new inbox rule or modifies an existing one using the Exchange admin center, PowerShell, or the Microsoft Graph API.
4.  The rule is configured to automatically delete emails containing specific keywords related to financial transactions or security alerts (T1566).
5.  Alternatively, the rule might forward all emails from specific internal addresses to an external account controlled by the attacker.
6.  The attacker uses the manipulated inbox to conceal their activities, such as unauthorized financial transactions or data exfiltration.
7.  The legitimate user remains unaware of the attacker's actions due to the automatic deletion or redirection of relevant emails.
8.  The attacker maintains persistence by ensuring the inbox rule remains active and undetected, allowing for continued unauthorized access and activity.

## Impact

Successful exploitation allows attackers to conceal malicious activity within the compromised account, intercept sensitive information, and maintain persistence. This can lead to significant financial losses due to BEC, data breaches, and reputational damage. Undetected inbox manipulation can also hinder incident response efforts by preventing security teams from identifying and containing the attack in a timely manner.

## Recommendation

*   Deploy the Sigma rule "Suspicious Inbox Manipulation Rules" to your SIEM and tune the `falsepositives` list with known good inbox rule behaviors in your organization.
*   Investigate any triggered alerts by examining the details of the created/modified inbox rules, focusing on their conditions and actions.
*   Review user sign-in logs for unusual activity preceding the creation of suspicious inbox rules, as described in the Microsoft documentation (https://learn.microsoft.com/en-us/entra/architecture/security-operations-user-accounts#unusual-sign-ins).
