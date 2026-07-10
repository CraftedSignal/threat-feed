---
title: O365 Email Receive and Hard Delete Takeover Behavior
slug: 2024-01-o365-email-delete
description: Compromised Office 365 accounts may receive and then hard delete emails related to password resets or banking/payroll changes, potentially indicating an attempt to redirect victim payroll to an attacker-controlled bank account.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - office365
  - account-takeover
  - email
  - data-destruction
vendors:
  - Microsoft
products:
  - Office 365
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
references:
  - https://attack.mitre.org/techniques/T1114/
  - https://www.hhs.gov/sites/default/files/help-desk-social-engineering-sector-alert-tlpclear.pdf
  - https://intelligence.abnormalsecurity.com/attack-library/threat-actor-convincingly-impersonates-employee-requesting-direct-deposit-update-in-likely-ai-generated-attack
rules:
  - title: O365 Email Hard Delete After Receiving Sensitive Email
    description: Detects O365 email hard deletes shortly after receiving an email with sensitive subject keywords.
    platform: sigma
    severity: high
    tactics:
      - collection
      - defense_evasion
      - impact
    techniques:
      - T1070.008
      - T1114.001
      - T1485
    data_sources:
      - office_365
      - o365
  - title: O365 Exchange Hard Delete Events
    description: Detects hard delete events in O365 Exchange, which can indicate data destruction or attacker cleanup.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1070.008
      - T1485
    data_sources:
      - office_365
      - o365
rules_count: 2
---

This analytic detects a specific account takeover behavior within Office 365 environments. It focuses on scenarios where a user receives emails containing sensitive information related to banking, payroll, or account recovery (e.g., password resets, MFA codes) and subsequently hard-deletes those emails within a short timeframe. This activity is indicative of a compromised account, where an attacker intercepts these sensitive communications and removes evidence of their activity. This attack is happening as of 2026-04-15 and is being detected using the Splunk Microsoft Office 365 Add-on by monitoring the Office 365 Universal Audit Log and Office 365 Reporting Message Trace. This is critical for defenders to identify compromised accounts used for financial fraud or data exfiltration.

## Attack Chain

1.  The attacker gains unauthorized access to an O365 user's account (likely through credential phishing or password reuse – techniques not explicitly detailed in the source).
2.  The compromised account receives emails with subjects containing keywords related to banking, direct deposit, pay-to, password, passcode, OTP, MFA, or account recovery.
3.  The attacker accesses the compromised user's inbox.
4.  The attacker identifies and reads emails containing sensitive information related to financial transactions or password resets.
5.  The attacker hard deletes the identified emails from the inbox, removing them from both the inbox and recoverable items.
6.  The deletion events are logged in the O365 management activity logs with `Operation` as `HardDelete` and the `Folder.Path` as either `\\Sent Items` or `\\Recoverable Items\\Deletions`.
7.  The attacker may then initiate fraudulent transactions, such as redirecting direct deposit information to a bank account under their control.

## Impact

A successful attack can result in financial losses for the victim, including unauthorized redirection of payroll funds. Attackers could use this access to conduct further malicious activities, such as sending phishing emails to other users or exfiltrating sensitive data. The impact can extend beyond individual users, potentially affecting the entire organization's financial stability and reputation. This type of attack can lead to significant financial damage and data breaches, with losses ranging from thousands to millions of dollars, depending on the scope of the compromise.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune for your environment to detect suspicious email deletion activity after receiving sensitive emails as defined by subject line keywords (`o365_messagetrace`, `o365_management_activity`).
*   Investigate any alerts triggered by the Sigma rule, focusing on users who receive and delete emails related to banking, payroll, or password resets.
*   Use the drilldown searches to investigate the user activity in the O365 environment based on the triggered alert (`user` field).
*   Implement multi-factor authentication (MFA) to reduce the risk of account compromise (reference: https://attack.mitre.org/techniques/T1114/).
*   Review and enforce strong password policies to prevent password reuse and reduce the risk of credential compromise.
