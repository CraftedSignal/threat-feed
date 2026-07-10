---
title: Google Workspace Object Copied from External Drive Followed by OAuth Consent
slug: 2024-05-09-gworkspace-drive-copy-oauth
description: Detects a sequence of events where a user copies a Google Workspace object (spreadsheet, form, document, or script) from an external drive and subsequently grants OAuth permissions to a custom application, potentially indicating a phishing attack leveraging container-bound scripts.
date: "2024-05-09T14:22:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - google-workspace
  - oauth
  - phishing
  - initial-access
  - persistence
vendors:
  - Google
products:
  - Google Workspace
  - Google Drive
  - Google Docs
  - Google Sheets
  - Google Forms
  - Google Apps Script
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
references:
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-one
  - https://www.elastic.co/security-labs/google-workspace-attack-surface-part-two
  - https://developers.google.com/apps-script/guides/bound
  - https://support.google.com/a/users/answer/13004165#share_make_a_copy_links
rules:
  - title: Google Workspace Drive Object Copy with OAuth Consent
    description: Detects a sequence of events where a Google Workspace object is copied from an external drive, followed by the user granting OAuth permissions to a custom application.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - persistence
    techniques:
      - T1098.001
      - T1566.002
    data_sources:
      - google_workspace
      - google_workspace
rules_count: 1
---

This detection identifies a specific attack vector within Google Workspace where a user is tricked into copying a file (such as a Google Sheet, Doc, Form, or Script) from an external Google Drive to their own. This is often achieved through phishing emails containing links with the "copy" parameter. These copied files may contain container-bound scripts. Upon opening the file, the user may be prompted to grant OAuth permissions to a seemingly legitimate application, which in reality is malicious and controlled by the attacker. The attacker leverages the user's granted permissions to access data or perform actions within the Google Workspace environment. This technique can be used to establish persistence, exfiltrate data, or further compromise the organization. This activity has been observed since March 2023.

## Attack Chain

1.  The attacker crafts a phishing email containing a link to a Google Drive object (e.g., Spreadsheet, Document) hosted on an external drive. The URL includes the "copy" parameter, tricking the victim into creating a copy of the object in their own Google Drive.
2.  The victim clicks the link and a copy of the Google Drive object is created in the victim's personal or corporate Google Drive. The object could be a script, form, spreadsheet, or document which can have container-bound scripts.
3.  The copied Google Drive object contains a container-bound script, designed to execute malicious code upon opening.
4.  When the user opens the copied object, the container-bound script triggers an OAuth prompt, requesting permissions to access the user's Google Workspace account. The prompt displays a custom application name.
5.  The user, believing the application is legitimate, grants the requested OAuth permissions. These permissions can include access to Gmail, Drive, Contacts, and other Google Workspace services.
6.  The malicious application, now possessing the granted OAuth tokens, gains access to the user's Google Workspace account and data.
7.  The attacker uses the compromised account to perform malicious actions, such as exfiltrating sensitive data, sending further phishing emails, or establishing persistence within the environment.

## Impact

A successful attack can result in unauthorized access to sensitive data stored in Google Workspace, including emails, documents, and spreadsheets. The attacker can also use the compromised account to spread malware or phishing attacks to other users within the organization. Depending on the granted OAuth permissions, the attacker may gain full control over the victim's Google Workspace account, leading to significant data loss, financial damage, and reputational harm. There has been no specific victim count or sector information.

## Recommendation

*   Deploy the Sigma rule "Google Workspace Drive Object Copy with OAuth Consent" to detect this attack pattern by monitoring Google Workspace logs for the "copy" event followed by OAuth authorization events.
*   Educate users on the risks of opening files from untrusted sources and granting OAuth permissions to unknown applications.
*   Review and audit OAuth applications that have been granted access to Google Workspace accounts, focusing on those with broad permissions and custom application IDs, as identified in the rule's description.
*   Monitor Google Workspace logs for the creation of new container-bound scripts, especially in files originating from external drives.
*   Reduce the `var.interval` within the Google Workspace Filebeat module to reduce the event lag time.
