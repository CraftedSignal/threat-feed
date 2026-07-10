---
title: O365 Data Loss Prevention Rule Triggered
slug: 2024-01-o365-dlp-rule-triggered
description: Detection of triggered Microsoft Office 365 Data Loss Prevention (DLP) rules, which can indicate potential data exfiltration or policy violations, dependent on upstream DLP configuration.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - data-exfiltration
  - o365
  - dlp
vendors:
  - Microsoft
products:
  - Office 365 Data Loss Prevention
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
references:
  - https://learn.microsoft.com/en-us/purview/dlp-learn-about-dlp
rules:
  - title: O365 DLP Rule Triggered
    description: Detects when a Microsoft Office 365 Data Loss Prevention (DLP) rule has been triggered.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1048
      - T1567
    data_sources:
      - o365
      - o365
  - title: O365 DLP Rule Triggered with Sensitive Information Type
    description: Detects when a specific sensitive information type triggers a DLP rule in O365.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1048
      - T1567
    data_sources:
      - o365
      - o365
rules_count: 2
---

This brief focuses on the detection of triggered Microsoft Office 365 Data Loss Prevention (DLP) rules within an organization. DLP rules are customizable policies designed to identify, monitor, and protect sensitive information, such as personally identifiable information (PII), financial data, or confidential business records. The efficacy of this detection relies entirely on the existing DLP configuration. The event source for this analytic is the Office 365 Universal Audit Log, as this provides granular insights into user activities and system events. Defenders should thoroughly evaluate detections stemming from triggered DLP events to determine security relevance, as the rules themselves can be noisy, and are only as accurate as their upstream configuration.

## Attack Chain

1. A user performs an action within the O365 environment (e.g., sending an email, sharing a file, or accessing a document).
2. The O365 DLP engine inspects the user's action and associated data for sensitive information based on configured rules.
3. A DLP rule is triggered if the user's action matches the defined conditions for sensitive data identification.
4. The triggering event is logged within the O365 Universal Audit Log, capturing details about the rule, user, and data involved.
5. The triggered rule may initiate automated actions such as blocking the email, restricting file access, or encrypting the data.
6. The event triggers the detection rule, alerting security analysts to the potential data loss or policy violation.
7. The analyst investigates the DLP rule trigger to determine if the event indicates a legitimate security concern or a false positive.

## Impact

A successful data exfiltration attempt, detected or prevented by DLP rules, can lead to the loss of sensitive data, regulatory fines, reputational damage, and competitive disadvantage. The number of affected individuals, the severity of the breach, and the financial impact are dependent on the volume and nature of the compromised data. Triggered DLP events may indicate insider threats, compromised accounts, or inadvertent policy violations.

## Recommendation

*   Deploy the Sigma rule `O365 DLP Rule Triggered` to your SIEM and tune for your environment to detect instances of DLP rule violations based on the `Office 365 Universal Audit Log`.
*   Review and refine existing O365 DLP rules to ensure accurate detection of sensitive information and minimize false positives, as mentioned in the overview.
*   Investigate triggered DLP rules to determine the underlying cause and take appropriate remediation actions, as described in the attack chain.
*   Monitor the O365 Universal Audit Log for events related to DLP rule triggers and user activities, using the data source specified.
