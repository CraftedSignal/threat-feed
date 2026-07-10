---
title: GSuite Email with Suspicious Attachment
slug: 2024-01-03-gsuite-suspicious-attachment
description: This analytic detects GSuite emails with suspicious file attachments (e.g., .exe, .bat, .js) which may indicate a spear-phishing attack leading to malware deployment and potential system compromise.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - gsuite
  - spear-phishing
  - malicious-attachment
vendors:
  - Google
products:
  - GSuite
  - Gmail
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.redhat.com/en/topics/devops/what-is-devsecops
rules:
  - title: GSuite Email with Suspicious Attachment
    description: Detects GSuite emails with attachments that have file extensions commonly associated with malware.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - dns_query
      - windows
  - title: GSuite Email Suspicious Attachment - Statistics
    description: This rule identifies suspicious email attachments based on the occurrence of specific file extensions in GSuite Gmail logs, providing statistical insights into potential spear-phishing attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

This analytic focuses on detecting potential spear-phishing attacks targeting GSuite users by identifying emails containing suspicious attachments. The detection leverages GSuite Gmail logs to identify emails with attachments having file extensions commonly associated with malware, such as .exe, .bat, .js, .vbs, .ps1 and others. The goal is to identify potentially malicious emails that bypass traditional security measures, such as spam filters. Successfully delivered malicious attachments can lead to unauthorized code execution, data breaches, or further network infiltration. This activity is significant as these file types are often used to deliver malicious payloads, posing a risk of compromising targeted machines. The alert is designed to detect anomalies that may indicate a sophisticated spear-phishing attempt.

## Attack Chain

1. An attacker crafts a spear-phishing email targeting a GSuite user.
2. The email contains an attachment with a suspicious file extension (e.g., .exe, .bat, .js, .vbs, .ps1).
3. The target user receives the email in their GSuite Gmail inbox.
4. The user opens the email and downloads the suspicious attachment.
5. The user executes the downloaded attachment, initiating the malicious payload.
6. The malicious payload executes, potentially compromising the user's machine.
7. The compromised machine establishes a connection to a command-and-control (C2) server.
8. The attacker gains remote access to the compromised machine, potentially leading to data exfiltration or further lateral movement within the network.

## Impact

A successful spear-phishing attack through GSuite can result in the compromise of individual user accounts and machines. This can lead to unauthorized access to sensitive data stored in GSuite, such as emails, documents, and contacts. It can also facilitate the deployment of malware on the compromised machine, potentially leading to data breaches, financial loss, and reputational damage. The impact is further amplified if the compromised user has privileged access to critical systems or data.

## Recommendation

*   Deploy the Sigma rule `GSuite Email with Suspicious Attachment` to your SIEM and tune for your environment based on the known_false_positives.
*   Enable alerting on the Sigma rule and prioritize investigation based on the `severity` field.
*   Implement user awareness training to educate employees about the risks of opening suspicious attachments and to recognize spear-phishing attempts.
*   Review and strengthen your organization's email security policies and procedures, focusing on attachment handling and malware prevention.
