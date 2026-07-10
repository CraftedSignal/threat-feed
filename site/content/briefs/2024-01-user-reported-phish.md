---
title: Detection of User-Reported Phishing or Malware in Office 365
slug: 2024-01-user-reported-phish
description: This detection identifies potentially malicious emails reported by users within an Office 365 environment through Security & Compliance policies, indicating possible phishing or malware attacks targeting the organization.
date: "2024-01-22T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - office365
  - phishing
  - user-reporting
vendors:
  - Microsoft
products:
  - Office 365
  - Outlook
  - Microsoft Defender for Office 365
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/o365/initial_access_security_compliance_user_reported_phish_malware.toml
rules:
  - title: O365 User Reported Phish or Malware
    description: Detects when a user reports a potential phishing email or malware through Security & Compliance policies.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - email
      - office365
  - title: O365 User Reported Phish - Investigation Recommended
    description: Flags user-reported phishing emails where the security and compliance center recommends further investigation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - email
      - office365
rules_count: 2
---

This detection rule focuses on identifying user-reported phishing or malware incidents within an Office 365 environment. When users report suspicious emails through the built-in reporting mechanisms in Outlook or other Microsoft services, these reports are aggregated and processed by the Security & Compliance center. The rule aims to detect these reports, which can be an early indicator of ongoing phishing campaigns or malware distribution attempts targeting employees. Timely detection of these reports allows security teams to investigate potential threats, assess the scope of the attack, and take appropriate remediation steps, such as quarantining malicious emails, blocking malicious senders, and alerting affected users. The scope of targeting depends on the specific campaign and the users targeted.

## Attack Chain

1.  **Phishing Email Delivery:** An attacker sends a phishing email to multiple users within the organization, attempting to deceive them into clicking a malicious link or opening a malicious attachment.
2.  **User Reports Suspicious Email:** A user identifies the email as suspicious and reports it using the built-in "Report Phishing" or "Report Junk" button within Outlook or another Microsoft email client.
3.  **Report Aggregation:** The reported email is sent to the configured reporting mailbox or processed by the Microsoft Defender for Office 365 Security & Compliance policies.
4.  **Security & Compliance Alert:** The Security & Compliance center generates an alert or log entry indicating that a user has reported a potential phishing email.
5.  **Detection Triggered:** This detection rule identifies the Security & Compliance alert related to user-reported phishing or malware.
6.  **Security Analyst Review:** A security analyst reviews the reported email, analyzes its contents, and investigates the sender's reputation and the linked URLs or attachments.
7.  **Incident Response:** Based on the analysis, the security team takes appropriate incident response actions, such as quarantining the email, blocking the sender, and alerting other potentially affected users.

## Impact

Successful phishing attacks can lead to credential compromise, malware infection, data exfiltration, and financial loss. By detecting user-reported phishing attempts, organizations can significantly reduce the risk of successful attacks and minimize the potential damage. The impact of a missed user report can range from a single compromised account to a widespread ransomware infection, depending on the sophistication and reach of the phishing campaign. Early detection is crucial to containing the threat and preventing further damage.
