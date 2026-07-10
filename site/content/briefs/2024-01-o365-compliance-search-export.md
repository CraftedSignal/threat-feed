---
title: O365 Compliance Content Search Exported
slug: 2024-01-o365-compliance-search-export
description: An adversary exports the results of an Office 365 Security and Compliance Center content search, potentially leading to data exfiltration of sensitive information.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - o365
  - data-exfiltration
  - compliance
vendors:
  - Microsoft
products:
  - Microsoft 365
  - Microsoft 365 Security and Compliance Center
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
  - title: O365 Compliance Content Search Exported
    description: Detects when a user exports content search results from the Office 365 Security and Compliance Center.
    platform: sigma
    severity: high
    tactics:
      - collection
    techniques:
      - T1114.002
    data_sources:
      - cloudtrail
      - o365
  - title: O365 Compliance Content Search Exported by Unusual User Agent
    description: Detects when a content search is exported from O365 using an unusual user agent.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1114.002
    data_sources:
      - cloudtrail
      - o365
rules_count: 2
---

The Office 365 Security and Compliance Center provides tools for searching and exporting content across the O365 environment. Attackers can abuse the compliance search functionality to identify and extract sensitive data from mailboxes, SharePoint sites, and other locations. By exporting the results of these searches, adversaries can bypass traditional data loss prevention (DLP) controls and exfiltrate data without triggering typical alerts. This activity is particularly concerning as it can expose sensitive organizational data and violate compliance regulations. The built-in "SearchExported" operation within the SecurityComplianceCenter workload provides defenders with an auditable event to detect this malicious activity within their O365 tenant.

## Attack Chain

1.  The attacker gains unauthorized access to an Office 365 account with sufficient permissions to access the Security & Compliance Center. This could be achieved through phishing, credential stuffing, or other methods of account compromise.
2.  The attacker logs into the Office 365 Security & Compliance Center.
3.  The attacker initiates a content search targeting specific keywords, custodians, or data locations. The search criteria are carefully chosen to identify sensitive information of interest.
4.  The attacker reviews the search results to validate the presence of the targeted sensitive data.
5.  The attacker initiates an export of the search results. This involves selecting an export format (e.g., PST, individual messages) and specifying an export location.
6.  The system processes the export request and prepares the data for download.
7.  The attacker downloads the exported data to their local system or an external storage location.
8.  The attacker exfiltrates the downloaded data from the compromised system to an external location under their control. This may involve using cloud storage, encrypted channels, or other methods to avoid detection. The attacker's goal is to steal sensitive data.

## Impact

Successful exploitation allows attackers to exfiltrate sensitive organizational data, including confidential emails, financial records, intellectual property, and customer data. This can lead to significant financial losses, reputational damage, legal liabilities, and regulatory fines. The number of affected individuals and the scope of the data breach will depend on the specific targets and search criteria used by the attacker. Organizations in regulated industries, such as finance and healthcare, are particularly vulnerable due to the strict data protection requirements they must adhere to.

## Recommendation

*   Monitor Office 365 management activity logs for "SearchExported" operations in the SecurityComplianceCenter workload to detect suspicious content search exports. Deploy the `O365 Compliance Content Search Exported` Sigma rule to your SIEM.
*   Implement multi-factor authentication (MFA) for all user accounts, especially those with administrative privileges to limit initial access (TA0001).
*   Regularly review and audit user permissions in Office 365 to ensure that users only have access to the data they need to perform their job functions.
*   Configure alerts for unusual or large-scale data exports from Office 365 to identify potential data exfiltration attempts.
*   Educate users about the risks of phishing and other social engineering attacks to prevent account compromise.
*   Investigate any detected "SearchExported" events promptly to determine the legitimacy of the export and identify any potential data breaches.
