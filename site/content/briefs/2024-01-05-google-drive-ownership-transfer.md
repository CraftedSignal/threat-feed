---
title: Google Drive Ownership Transferred via Google Workspace
slug: 2024-01-05-google-drive-ownership-transfer
description: Adversaries may transfer files to an adversary account for potential exfiltration by abusing Google Workspace administration permissions to transfer file ownership within Google Drive.
date: "2024-01-05T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - google-workspace
  - data-exfiltration
  - cloud
vendors:
  - Google
products:
  - Google Drive
  - Google Docs
  - Google Workspace
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
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two
  - https://support.google.com/a/answer/7587183
rules:
  - title: Detect Google Workspace Drive Ownership Transfer
    description: Detects Google Workspace data transfer requests in Google Drive, potentially indicating malicious exfiltration attempts.
    platform: sigma
    severity: medium
    tactics:
      - collection
      - exfiltration
    techniques:
      - T1537
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Google Workspace Admin Activity
    description: Detects unusual admin activity within Google Workspace by monitoring admin logs for specific events.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Google Drive and Docs is a Google Workspace service that allows users to leverage Google Drive and Google Docs. Access to files is based on inherited permissions from the child organizational unit the user belongs to which is scoped by administrators. If a user is removed, their files can be transferred to another user by the administrator. This service can be abused by adversaries to transfer files to an adversary account for potential exfiltration. Google Workspace administrators consider users' roles and organizational units when assigning permissions to files or shared drives. This rule identifies when the ownership of a shared drive within a Google Workspace organization is transferred to another internal user.

## Attack Chain

1. An adversary gains initial access to a compromised Google Workspace account or obtains administrative privileges.
2. The adversary identifies a target user or shared drive containing sensitive data within the Google Workspace environment.
3. The adversary initiates a data transfer request within Google Workspace, targeting an account under their control. This is achieved by creating a "CREATE_DATA_TRANSFER_REQUEST" event for the Drive application.
4. The Google Workspace administrator reviews and approves the data transfer request (or the adversary leverages compromised admin credentials to approve the request).
5. Google Workspace initiates the transfer of files and folders from the original owner to the adversary-controlled account.
6. Data is staged in the adversary's account.
7. The adversary exfiltrates the transferred data from their Google Drive account to an external location.
8. The adversary covers their tracks by deleting logs or modifying permissions (actions not explicitly detailed in source).

## Impact

A successful Google Drive ownership transfer can lead to the exfiltration of sensitive data, including confidential documents, financial records, and proprietary information. This could result in financial loss, reputational damage, and legal liabilities. While the specific number of victims and sectors targeted is not mentioned in the provided context, any organization using Google Workspace is potentially vulnerable.

## Recommendation

*   Deploy the Sigma rule `Detect Google Workspace Drive Ownership Transfer` to your SIEM to detect unauthorized data transfer requests based on `event.action:"CREATE_DATA_TRANSFER_REQUEST"` and `google_workspace.admin.application.name:Drive*`.
*   Review Google Workspace admin logs for involved user accounts as mentioned in the investigation guide to identify potentially compromised accounts.
*   Enforce the principle of least privilege by regularly reviewing and restricting Google Drive permissions for users and shared drives, following Google's security best practices outlined [here](https://support.google.com/a/answer/7587183).
*   Reduce the `var.interval` of the Google Workspace Filebeat module to 10 minutes (10m) to minimize the risk of missing data transfer events due to Google Workspace event lag times.
