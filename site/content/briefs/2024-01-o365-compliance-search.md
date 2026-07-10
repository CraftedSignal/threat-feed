---
title: O365 Compliance Content Search Activity Detected
slug: 2024-01-o365-compliance-search
description: Detection of content search initiation within the Office 365 Security and Compliance Center using the SearchCreated operation, which may signal unauthorized access to sensitive organizational data such as emails and documents, potentially leading to data exfiltration and compliance breaches.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - o365
  - compliance
  - content search
  - data exfiltration
vendors:
  - Microsoft
products:
  - Microsoft 365
  - Office 365
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
references:
  - https://attack.mitre.org/techniques/T1114/002/
  - https://learn.microsoft.com/en-us/purview/ediscovery-content-search-overview
  - https://learn.microsoft.com/en-us/purview/ediscovery-keyword-queries-and-search-conditions
  - https://learn.microsoft.com/en-us/purview/ediscovery-search-for-activities-in-the-audit-log
rules:
  - title: O365 Compliance Content Search Started
    description: Detects when a content search is initiated within the Office 365 Security and Compliance Center. This activity is significant as it may indicate an attempt to access sensitive organizational data.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1114.002
    data_sources:
      - cloud
      - o365
  - title: O365 Compliance Content Search - High Volume
    description: Detects a high volume of content searches initiated from a single user within a short period, which could indicate malicious activity.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1114.002
    data_sources:
      - cloud
      - o365
rules_count: 2
---

This analytic identifies the initiation of content searches within the Office 365 Security and Compliance Center, an activity that can indicate attempts to access sensitive data. The detection focuses on the "SearchCreated" operation within the o365_management_activity logs, specifically from the SecurityComplianceCenter workload. Content searches, while sometimes legitimate, can also be used maliciously to identify and access confidential emails, documents, and other sensitive information. Successful exploitation can lead to unauthorized data access, data exfiltration, and significant compliance violations, potentially impacting a broad range of organizations utilizing Microsoft 365 services. Defenders should monitor these events closely to differentiate between legitimate use and potential malicious activity, particularly when combined with other suspicious behaviors.

## Attack Chain

1.  The attacker gains initial access to a compromised or rogue user account within the target Office 365 environment, possibly through phishing or credential stuffing.
2.  The attacker authenticates to the Office 365 environment using the compromised account.
3.  The attacker navigates to the Office 365 Security and Compliance Center.
4.  The attacker initiates a content search using the "SearchCreated" operation, targeting specific mailboxes or SharePoint sites.
5.  The attacker defines search criteria to identify sensitive data, potentially using keywords or specific date ranges.
6.  The system executes the content search and the results are stored.
7.  The attacker accesses the search results, reviewing sensitive emails or documents.
8.  The attacker exfiltrates the sensitive data from the Office 365 environment, potentially through email, cloud storage, or other means.

## Impact

Successful exploitation can lead to unauthorized access and exfiltration of sensitive organizational data, including emails, documents, and other confidential information. This can result in significant financial losses, reputational damage, legal liabilities, and compliance violations. Depending on the scope and nature of the data compromised, the impact could range from individual privacy breaches to large-scale corporate espionage. Organizations in regulated industries such as finance, healthcare, and government are particularly vulnerable due to the sensitive nature of the data they handle.

## Recommendation

*   Ensure proper installation and configuration of the Splunk Microsoft Office 365 Add-on to ingest relevant Office 365 management activity events.
*   Deploy the Sigma rule `O365 Compliance Content Search Started` to your SIEM and tune for your environment, paying close attention to known false positives.
*   Investigate any detected `SearchCreated` events, focusing on the user initiating the search, the targets of the search, and the search criteria used.
*   Monitor for unusual network activity or data exfiltration following a detected content search.
*   Implement multi-factor authentication (MFA) to protect against compromised accounts, reducing the risk of unauthorized access.
