---
title: O365 Email Reported by Admin Found Malicious
slug: 2024-01-o365-email-reported-malicious
description: Detection of emails manually submitted to Microsoft through the Security & Compliance portal and subsequently identified as malicious (Phish or Malware).
date: "2024-01-02T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - o365
  - email
  - malware
  - phishing
vendors:
  - Microsoft
products:
  - Microsoft 365
  - Office 365
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/submissions-outlook-report-messages?view=o365-worldwide
rules:
  - title: O365 Email Reported By Admin Found Malicious
    description: Detects when an email manually submitted to Microsoft through the Security & Compliance portal is found to be malicious.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.001
      - T1566.002
    data_sources:
      - Office 365 Universal Audit Log
      - o365
  - title: O365 Admin Submission with Suspicious Subject
    description: Detects O365 Admin Submissions with subject lines commonly used in phishing campaigns.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - Office 365 Universal Audit Log
      - o365
rules_count: 2
---

This detection focuses on identifying malicious emails within Microsoft 365 environments that have been reported by administrators through the Security & Compliance portal. This feature allows administrators to proactively submit suspicious emails for analysis. The analytic triggers when a submitted email receives a "Phish" or "Malware" verdict upon analysis by Microsoft's systems. This capability is an enhanced protection feature that can be used within o365 tenants by administrative users to report potentially malicious emails. This detection is valuable because it highlights cases where human intuition, combined with automated analysis, confirms a malicious email that may have bypassed initial security filters. This insight allows security teams to quickly respond to potential phishing or malware campaigns.

## Attack Chain

1.  An attacker sends a phishing or malware-laden email to a user within the organization.
2.  The email bypasses initial security filters and reaches the user's inbox.
3.  An administrator, suspecting the email is malicious, manually submits the email for analysis through the Microsoft Security & Compliance portal using the Admin Submission feature.
4.  Microsoft's systems analyze the submitted email, examining its content, links, and attachments.
5.  The analysis returns a verdict of either "Phish" or "Malware", confirming the malicious nature of the email.
6.  The "AdminSubmission" event is logged within the Office 365 Unified Audit Log, containing details about the submission, sender, recipients, and the verdict.
7.  The detection analytic identifies the "AdminSubmission" event with a "Phish" or "Malware" verdict.
8.  Security teams can investigate the reported email, block the sender, and identify other potentially affected users to prevent further compromise.

## Impact

A successful phishing or malware campaign can lead to credential theft, data breaches, and ransomware infections. Even a single successful compromise can have significant financial and reputational consequences. This detection helps identify emails that have bypassed initial security layers, potentially preventing a successful attack.

## Recommendation

*   Deploy the Sigma rule `O365 Email Reported By Admin Found Malicious` to your SIEM to detect malicious emails reported by administrators.
*   Investigate any alerts triggered by the `O365 Email Reported By Admin Found Malicious` rule, focusing on the sender and recipients of the reported email.
*   Block sender addresses associated with confirmed malicious emails at the email gateway (reference the source IP from the logs).
*   Correlate `AdminSubmission` events with other security logs to identify potentially related malicious activities (e.g., failed login attempts, unusual file access).
*   Configure the Microsoft Office 365 add-on in Splunk to collect the necessary `o365:management:activity` logs.
