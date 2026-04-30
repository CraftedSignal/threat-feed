---
title: Silver Fox Spearphishing Campaign Targeting Japanese Firms During Tax Season
slug: 2026-03-silverfox-japan-tax-season
description: The Silver Fox threat actor is conducting a targeted spearphishing campaign against Japanese manufacturers and other businesses, exploiting the annual tax filing and organizational change season by sending emails containing malicious attachments that deploy ValleyRAT, leading to remote access, data theft, and persistence.
date: "2026-03-28T12:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Silver Fox
tags:
  - silverfox
  - spearphishing
  - valleyrat
  - japan
  - taxseason
  - remoteaccesstrojan
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.welivesecurity.com/en/business-security/cunning-predator-how-silver-fox-preys-japanese-firms-tax-season/
rules:
  - title: Detect ValleyRAT Execution
    description: Detects the execution of ValleyRAT, a remote access trojan used by Silver Fox.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious Archive Download from File Sharing Services
    description: Detects suspicious downloads of archive files (ZIP, RAR) from file sharing services often used for malicious payload delivery.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The Silver Fox threat actor, active since at least 2023, is conducting a spearphishing campaign targeting Japanese organizations during their annual tax filing and organizational change season. Initially focused on Chinese-speaking targets, Silver Fox has expanded its operations into Southeast Asia, Japan, and potentially North America. This campaign specifically exploits the high volume of legitimate financial and HR-related communications that occur during this period, making it more likely that employees will trust and act on malicious messages related to tax compliance violations, salary adjustments, job position changes, and employee stock ownership plans. The group has targeted a range of verticals including finance, healthcare, education, gaming, government and cybersecurity. This campaign is a repeat of similar activity observed during the same period last year, indicating a deliberate alignment of operations with this seasonal business cycle.

## Attack Chain

1.  The attacker performs reconnaissance on targeted Japanese companies, gathering information on employee names and roles within HR and finance departments.
2.  Spearphishing emails are crafted to impersonate real employees or even CEOs at the targeted companies. The emails often include the targeted company's name in the subject line to enhance credibility.
3.  The emails are sent to employees during Japan's tax filing and organizational change season, increasing the likelihood of the recipients opening the messages due to the expected volume of HR and financial communications.
4.  The emails contain malicious attachments, such as ZIP or RAR archives, or links leading to malicious files hosted on public file-sharing services like gofile[.]io or WeTransfer.
5.  The malicious files are named to resemble common HR, financial, or tax-related documents, such as "Salary Adjustment Notice" or "Notice regarding personnel changes and salary adjustments."
6.  When the recipient opens the malicious file, it drops ValleyRAT (detected as Win64/Valley by ESET products), a remote access trojan.
7.  ValleyRAT enables the attacker to take remote control of the compromised machine, harvest sensitive information, and monitor user activity.
8.  The attacker establishes persistence within the targeted environment, allowing for continued access and the potential for further malicious activities, such as data exfiltration or deploying additional malware.

## Impact

Successful exploitation of this campaign can lead to a significant compromise of Japanese organizations, particularly manufacturers and businesses involved in finance, healthcare, education, gaming, government and cybersecurity. The deployment of ValleyRAT allows the attacker to gain remote access to compromised systems, potentially leading to the theft of sensitive financial data, intellectual property, and confidential employee information. This can result in financial losses, reputational damage, and legal repercussions for the affected organizations.

## Recommendation

*   Deploy the "Detect ValleyRAT Execution" Sigma rule to identify instances where ValleyRAT is executed on endpoints (Sigma rule).
*   Monitor email traffic for subjects containing company names along with keywords related to tax, HR, and salary adjustments, and alert on unusual patterns (email logs).
*   Block connections to known malicious file hosting services like gofile[.]io and WeTransfer at the network level, as these are used to deliver the malicious payloads (network_connection logs).
*   Educate employees to verify any requests related to salary changes, tax penalties, or personnel updates through separate channels (awareness training).
*   Implement multi-factor authentication (MFA) for all email accounts to prevent unauthorized access (authentication logs).
