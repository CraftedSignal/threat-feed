---
title: Gsuite Email with Suspicious Subject and Attachments
slug: 2024-01-gsuite-phishing-attachments
description: Detection of Gsuite emails with suspicious subjects and attachments (e.g., DHL, UPS, invoice, DOC, ZIP) indicative of spear phishing, excluding internal test domains, which could lead to initial compromise and further malicious activity.
date: "2024-01-03T15:22:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - spear-phishing
  - initial-access
  - gsuite
vendors:
  - Google
products:
  - Gsuite
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.redhat.com/en/topics/devops/what-is-devsecops
  - https://www.mandiant.com/resources/top-words-used-in-spear-phishing-attacks
iocs:
  - type: domain
    value: internal_test_email.com
ioc_counts:
  domain: 1
rules:
  - title: Gsuite Email Suspicious Attachment Type
    description: Detects Gsuite emails with attachments of file types commonly used in malware distribution or phishing attacks.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - email
      - gsuite
  - title: Gsuite Email Suspicious Subject Keywords
    description: Detects Gsuite emails with subject lines containing keywords commonly used in phishing lures.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - email
      - gsuite
rules_count: 2
---

This brief addresses the risk of spear phishing attacks delivered via Gsuite email. The detection focuses on emails with subject lines containing keywords commonly associated with phishing lures, such as shipping companies (DHL, UPS, FedEx, USPS), delivery notifications, invoices, and orders. It also analyzes email attachments for file types frequently used to deliver malware or malicious content (e.g., DOC, XLS, PDF, ZIP, HTML). Communications originating from or destined for the 'internal_test_email.com' domain are excluded. This detection logic aims to identify potentially malicious emails that bypass basic spam filters and target users with tailored lures, which began in 2026. Successful attacks of this type can lead to credential theft, malware infection, and data breaches.

## Attack Chain

1.  The attacker crafts a spear phishing email with a subject line containing keywords related to shipping, delivery, or invoices to entice the recipient.
2.  The email includes a malicious attachment, such as a Microsoft Word document (.doc or .docx), an Excel spreadsheet (.xls or .xlsx), a PDF file (.pdf), or a compressed archive (.zip or .rar).
3.  The recipient opens the email and, prompted by the subject line, opens the attachment.
4.  If the attachment is a document or spreadsheet, it may contain malicious macros or embedded code that executes upon opening.
5.  If the attachment is an archive, it may contain an executable file or a malicious script that the user is tricked into running.
6.  Upon execution, the malicious code may install malware, establish a connection to a command-and-control (C2) server, or steal sensitive information.
7.  The malware may then spread laterally within the organization's network, compromise additional systems, and exfiltrate sensitive data.
8. The attacker achieves their final objective, such as data exfiltration, ransomware deployment, or long-term access to the compromised environment.

## Impact

Successful spear phishing attacks can result in significant damage to an organization. This includes the compromise of user accounts, the loss of sensitive data, the disruption of business operations, and financial losses due to incident response, recovery efforts, and potential regulatory fines. Spear phishing is a common vector for ransomware deployment, which can cripple an organization's infrastructure and lead to significant financial losses and reputational damage. The number of potential victims is limited to the number of employees or users who have access to Gsuite email.

## Recommendation

*   Deploy the "Gsuite Email Suspicious Subject With Attachment" analytic as a starting point for detection, and tune the keyword list and attachment file type list for your specific environment.
*   Enable and review Gsuite Gmail logs, ensuring that attachment metadata (file type, extension, SHA256 hash) is being ingested (as described in "how_to_implement") to ensure the detection rule functions correctly.
*   Block the domain `internal_test_email.com` at your email gateway to prevent any potential abuse of this testing domain, as referenced in the IOC section.
