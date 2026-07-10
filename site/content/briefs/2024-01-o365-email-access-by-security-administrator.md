---
title: O365 Email Access By Security Administrator
slug: 2024-01-o365-email-access-by-security-administrator
description: Atypical access to O365 mailboxes is detected when a security administrator uses Threat Explorer features to directly view email, potentially indicating reconnaissance or data exfiltration by a compromised or malicious insider.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - o365
  - data exfiltration
  - azure ad
vendors:
  - Microsoft
products:
  - Office 365
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1567
    technique_name: Unusual File Access
references:
  - https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/threat-explorer-investigate-delivered-malicious-email?view=o365-worldwide
rules:
  - title: O365 Email Access By Security Administrator
    description: Detects when a security administrator accesses email using the AdminMailAccess feature in Threat Explorer.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1114.002
      - T1567
    data_sources:
      - webserver
      - o365
  - title: O365 Email Access By Security Administrator - Multiple Accesses
    description: Detects when a security administrator accesses multiple email messages using the AdminMailAccess feature in Threat Explorer within a short timeframe.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1114.002
      - T1567
    data_sources:
      - webserver
      - o365
rules_count: 2
---

This detection identifies instances where a user with administrative privileges in the Office 365 Security & Compliance center utilizes the "AdminMailAccess" feature, specifically within Threat Explorer, to directly view email content. Threat Explorer is a premium feature within O365 that provides security teams with enhanced investigation capabilities. Attackers may abuse these elevated privileges to gain unauthorized access to sensitive information, enumerate high-value targets, or exfiltrate data. This behavior is flagged as anomalous as it deviates from the intended use case of incident response and threat hunting, highlighting potential misuse of administrative access. The activity is logged within the Office 365 Universal Audit Log.

## Attack Chain

1. An adversary gains unauthorized access to an Office 365 account with Security Administrator privileges, potentially via credential compromise (phishing, password spraying).
2. The attacker logs into the Office 365 Security & Compliance center.
3. The attacker navigates to the Threat Explorer section within the Security & Compliance center.
4. The attacker uses the "AdminMailAccess" feature within Threat Explorer to view the contents of specific mailboxes. This action generates an "AdminMailAccess" event in the O365 audit logs.
5. The attacker enumerates sensitive information contained within the accessed emails, identifying data of interest.
6. The attacker may exfiltrate the sensitive information obtained from the mailboxes via various methods, such as forwarding emails, downloading attachments, or copying data.
7. The attacker attempts to cover their tracks by deleting audit logs or modifying user permissions (not covered by this detection).

## Impact

Successful exploitation could lead to unauthorized access and exfiltration of sensitive data from Office 365 mailboxes. This can result in financial loss, reputational damage, and legal liabilities due to data breaches. The impact is directly correlated with the sensitivity of the data stored within the targeted mailboxes. The detection triggers when a security administrator views email using Threat Explorer features, but the total number of affected mailboxes or the specific data exfiltrated isn't directly available from this single event.

## Recommendation

*   Deploy the Sigma rule `O365 Email Access By Security Administrator` to your SIEM to identify potential malicious use of AdminMailAccess.
*   Investigate any alerts triggered by the `O365 Email Access By Security Administrator` rule, focusing on the context of the administrative user's activity and the target mailboxes.
*   Review the Microsoft Office 365 audit logs for other suspicious activities performed by the involved administrator account around the time of the email access event.
*   Implement multi-factor authentication (MFA) for all administrator accounts to mitigate the risk of credential compromise.
*   Regularly review and audit the permissions assigned to administrator accounts to ensure the principle of least privilege.
*   Educate security administrators on the proper use of Threat Explorer and the potential risks associated with unauthorized mailbox access.
