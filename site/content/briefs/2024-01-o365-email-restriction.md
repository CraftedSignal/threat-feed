---
title: Office 365 User Restricted from Sending Email
slug: 2024-01-o365-email-restriction
description: An Office 365 user account is restricted from sending email, potentially indicating account compromise, policy violation, or administrative action following suspicious activity.
date: "2024-01-09T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - o365
  - email
  - account-compromise
vendors:
  - Microsoft
products:
  - Office 365
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/o365/initial_access_security_compliance_user_restricted_from_sending_email.toml
rules:
  - title: Office 365 User Email Sending Restriction
    description: Detects events where an Office 365 user is restricted from sending email, indicating potential account compromise or policy violation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - office365
      - o365
  - title: Office 365 Suspicious Email Activity Leading to Restriction
    description: Detects patterns suggesting malicious email activity shortly before a user is restricted, focusing on high volumes of external recipients.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - initial_access
    techniques:
      - T1071.001
      - T1566
    data_sources:
      - office365
      - o365
rules_count: 2
---

This alert focuses on detecting when an Office 365 user is restricted from sending email. This event can occur due to various reasons, including a compromised account exhibiting spamming behavior, a violation of company email policies, or as a direct result of administrative intervention following the detection of suspicious activity. While not inherently malicious, this event serves as a strong indicator requiring further investigation to determine the root cause and potential security implications. The trigger for this event is logged within the Office 365 Security and Compliance Center. The investigation should aim to understand why the restriction was put in place, the user's recent activity, and the potential impact on the organization.

## Attack Chain

1. **Initial Access:** An attacker gains unauthorized access to an Office 365 user account, potentially through credential phishing, brute-force attacks, or password reuse.
2. **Internal Reconnaissance:** The attacker explores the compromised account, identifying sensitive information, contacts, and internal resources.
3. **Email Spamming/Phishing:** The attacker uses the compromised account to send out spam or phishing emails to internal and external recipients.
4. **Detection of Anomalous Activity:** Office 365 security systems detect the anomalous email sending activity based on volume, content, or recipient patterns.
5. **Administrative Action:** An administrator or automated system responds to the detected anomaly by restricting the user's ability to send email.
6. **Restriction Implementation:** The restriction is implemented at the Office 365 level, preventing the user from sending further emails.
7. **Notification Event:** An event is logged in the Office 365 Security and Compliance Center indicating that the user has been restricted from sending email.
8. **Investigation and Remediation:** Security team investigates, confirms the compromise, and implements remediation steps like password reset, MFA enforcement, and endpoint isolation.

## Impact

A restricted user account can disrupt business operations, especially if the user is critical for communication. If the restriction is due to a compromised account, the organization may suffer reputational damage, data breaches, or financial losses. The number of impacted users depends on the scope of the compromise and the speed of detection and response. Targeted sectors are broad, as email compromise affects all industries. Successful attacks leading to account restrictions highlight weaknesses in access controls and security awareness, potentially inviting further attacks.
