---
title: Google Workspace Drive Data Transfer or Takeout Export Initiated
slug: 2026-05-google-workspace-drive-data-transfer
description: This rule detects when Google Workspace administrators initiate bulk movement or export of user Drive data, including admin data transfer requests and Customer Takeout export jobs which can be abused by adversaries with administrative access to stage or exfiltrate sensitive files.
date: "2026-05-28T15:40:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - google_workspace
  - data_exfiltration
  - cloud
vendors:
  - Google
products:
  - Google Workspace
  - Google Drive
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1074
    technique_name: Data Staged
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
references:
  - https://support.google.com/a/answer/1247799?hl=en
  - https://support.google.com/a/answer/10276199
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two
rules:
  - title: Detect Google Workspace Drive Data Transfer Request
    description: Detects creation of Google Workspace data transfer requests, indicating a potential data exfiltration attempt.
    platform: sigma
    severity: medium
    tactics:
      - collection
    techniques:
      - T1074.002
    data_sources:
      - admin
      - google_workspace
  - title: Detect Google Workspace Customer Takeout Export
    description: Detects initiation of a Google Workspace Customer Takeout export, which could be used for exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - admin
      - google_workspace
rules_count: 2
---

The Google Workspace environment allows administrators to perform bulk data transfers of user Drive files to other in-domain accounts, as well as create Customer Takeout exports that package user or organizational data for download or transfer to external destinations. An adversary with compromised administrator credentials may abuse these features to collect sensitive files without needing to modify per-file sharing permissions. This activity is often conducted during the collection and exfiltration phases of an attack. The rule detects `CREATE_DATA_TRANSFER_REQUEST` events with Drive application scope and `CUSTOMER_TAKEOUT_CREATED` events within Google Workspace admin logs, providing visibility into potential data theft by malicious insiders or external attackers who have gained administrative privileges. Defenders should investigate any unexpected data transfer or takeout export activities to determine their legitimacy and potential impact.

## Attack Chain

1.  An attacker gains unauthorized access to a Google Workspace administrator account, potentially through credential compromise or phishing.
2.  The attacker authenticates to the Google Workspace Admin console using the compromised credentials.
3.  The attacker initiates a data transfer request to reassign a user's Drive files to another account within the same Google Workspace domain using `CREATE_DATA_TRANSFER_REQUEST`.
4.  Alternatively, the attacker initiates a Customer Takeout export job (`CUSTOMER_TAKEOUT_CREATED`) to package organizational data for download. This may involve specifying a Google-provided bucket or a customer-owned Cloud Storage location.
5.  The Google Workspace system processes the data transfer or export request.
6.  For data transfer requests, the designated target account receives ownership or access to the transferred files.
7.  For Customer Takeout exports, the data is packaged into an archive.
8.  The attacker downloads the archive from the designated storage location or accesses the data through the target account, achieving exfiltration or staging of sensitive data.

## Impact

A successful attack could result in the exfiltration of sensitive company data, intellectual property, or personal information stored within Google Drive. The number of affected users depends on the scope of the data transfer or takeout export. Targeted sectors could vary depending on the nature of the compromised administrator account and the data it has access to. The damage could include financial loss, reputational damage, legal liabilities, and compromise of competitive advantages.

## Recommendation

*   Deploy the Sigma rule "Google Workspace Drive Data Transfer or Takeout Export Initiated" to your SIEM to detect suspicious data transfer or takeout export activities.
*   Review admin logs for involved user accounts as described in the rule's "Possible investigation steps" section.
*   For Customer Takeout events, pivot on `google_workspace.admin.OBFUSCATED_CUSTOMER_TAKEOUT_REQUEST_ID` in Elasticsearch to find related admin events for the same export job.
*   Implement security best practices outlined by Google to prevent credential compromise and unauthorized access to administrator accounts as referenced in the [Google security best practices](https://support.google.com/a/answer/7587183) reference.
*   Monitor the `user.email`, `user.target.email`, and `google_workspace.admin.new_value` fields in the logs to track the initiator, source, and destination users involved in data transfer requests.
*   Reduce the interval that the Google Workspace Filebeat module polls Google's reporting API for new events to mitigate event lag times as mentioned in the Setup section.
