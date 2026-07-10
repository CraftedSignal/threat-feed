---
title: O365 Email Reported by User Found Malicious
slug: 2024-01-o365-email-reported-malicious
description: Detection of emails reported by users as malicious via the Outlook 'Report Message' feature, subsequently confirmed as Phish or Malware by Microsoft's analysis, indicating successful initial access.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - o365
  - phishing
  - malware
  - email
vendors:
  - Microsoft
products:
  - Microsoft 365
  - Outlook
  - Exchange Online Protection
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
  - title: O365 Email Reported By User Found Malicious
    description: Detects when an email reported by a user in O365 is found to be malicious by Microsoft's analysis.
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
  - title: O365 Email Reported By User - Extract Sender
    description: Extracts the sender of an email reported by a user that was later classified as malicious.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1566.001
      - T1566.002
    data_sources:
      - Office 365 Universal Audit Log
      - o365
rules_count: 2
---

This detection focuses on identifying malicious emails that bypass initial security layers and reach end-users, who then report them using the 'Report Message' feature in Outlook. When a user reports an email, Microsoft analyzes it and provides a verdict. This alert triggers when a user-reported email is classified as either "Phish" or "Malware," indicating a successful initial access attempt by the attacker. This feature provides an enhanced security layer, empowering users to actively participate in threat detection. The targeted scope is O365 tenants utilizing the Microsoft Office Report A Message function.

## Attack Chain

1.  Attacker crafts a phishing email with malicious content (e.g., a link to a credential harvesting site or a malware-laden attachment).
2.  The email bypasses automated security filters (e.g., Exchange Online Protection) and lands in the user's inbox.
3.  The user, recognizing the suspicious nature of the email, utilizes the "Report Message" feature in Outlook to flag the email to Microsoft.
4.  Microsoft's systems analyze the reported email and identify it as either "Phish" or "Malware," based on its characteristics and content.
5.  An AlertEntityGenerated event is created in the Office 365 Universal Audit Log, signaling that a user-reported email has been confirmed as malicious.
6.  The detection rule identifies this event and extracts relevant information, such as sender, subject, and reporting user.
7.  Security analysts investigate the incident to determine the scope and impact of the phishing campaign.
8.  Compromised accounts are remediated, and security controls are updated to prevent similar attacks in the future.

## Impact

A successful phishing attack can lead to credential theft, malware infections, and data breaches. If a reported email is classified as malicious, it indicates that the attacker has successfully bypassed initial security measures and reached an end-user. The number of affected users depends on the scale of the phishing campaign. Targeted sectors include any organization utilizing Microsoft 365 services. Successful attacks can lead to significant financial losses, reputational damage, and legal liabilities.

## Recommendation

*   Enable and promote the use of the Microsoft Office "Report Message" function to empower users to report suspicious emails (Reference: https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/submissions-outlook-report-messages?view=o365-worldwide).
*   Install the Splunk Microsoft Office 365 Add-on to ingest Office 365 management activity events (See: How to Implement section).
*   Deploy the Sigma rule `O365 Email Reported By User Found Malicious` to your SIEM and tune for your environment.
*   Investigate users who report malicious emails to identify potential compromises.
*   Use the drilldown searches to pivot to risk events for the reporting user and email sender to determine any additional suspicious activity.
