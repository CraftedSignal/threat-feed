---
title: Unusual Volume of File Deletion in Microsoft 365
slug: 2024-01-unusual-file-deletion
description: An attacker may delete an unusual volume of files in Microsoft 365 to cause disruption or hide malicious activity.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - microsoft365
  - file_deletion
  - data_loss
  - impact
vendors:
  - Microsoft
products:
  - Microsoft 365
  - SharePoint
  - OneDrive
  - Teams
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/o365/impact_security_compliance_unusual_volume_of_file_deletion.toml
rules:
  - title: Detect Unusual Volume of File Deletion Events
    description: Detects a user deleting an unusually high number of files within a short timeframe in Microsoft 365.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - file_event
      - windows
  - title: Detect Microsoft 365 User Deletion Activity
    description: Detects Microsoft 365 user deletion activity through the Office 365 Management Activity API.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1564.003
    data_sources:
      - web
      - office_365
rules_count: 2
---

This activity focuses on the potential impact of an attacker deleting a significant number of files within a Microsoft 365 environment. While the provided source doesn't explicitly attribute this behavior to a specific threat actor or campaign, it highlights the importance of detecting unusual file deletion patterns, regardless of the cause. Attackers can leverage this technique to disrupt business operations by causing data loss or to cover their tracks after gaining unauthorized access to sensitive information. The scope of this threat is potentially broad, affecting any organization relying on Microsoft 365 for file storage and collaboration.

## Attack Chain

1.  **Initial Access:** An attacker gains unauthorized access to a Microsoft 365 account, potentially through phishing or credential compromise.
2.  **Privilege Escalation (Optional):** The attacker may attempt to escalate privileges within the Microsoft 365 environment to gain broader access to files and folders.
3.  **Discovery:** The attacker identifies valuable data stored within SharePoint, OneDrive, or Teams.
4.  **Data Manipulation:** The attacker begins deleting a large number of files and folders within a short period.
5.  **Evasion:** The attacker may attempt to disable or tamper with audit logs to prevent detection of their activity.
6.  **Impact:** Legitimate users are unable to access critical data, leading to business disruption and potential data loss.

## Impact

A successful attack involving the unusual deletion of files can lead to significant data loss, business disruption, and reputational damage. Depending on the scope of the deletion, organizations may face challenges in recovering lost data, leading to prolonged downtime and financial losses. The sectors most vulnerable are those heavily reliant on Microsoft 365 for daily operations and data storage.
