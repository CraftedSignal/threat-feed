---
title: Microsoft 365 Suspicious Email Delivery
slug: 2024-01-m365-suspicious-email
description: This brief outlines a threat where Microsoft Defender for Office 365 identifies an email as malicious or suspicious but still delivers it to a user's inbox or junk folder, potentially bypassing initial security measures.
date: "2024-01-03T12:00:00Z"
severities:
  - medium
tags:
  - suspicious-email
  - phishing
  - microsoft365
vendors:
  - Microsoft
products:
  - Microsoft 365
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://learn.microsoft.com/en-us/defender-office-365/threat-explorer-real-time-detections-about
  - https://research.splunk.com/cloud/605cc93a-70e4-4ee3-9a3d-1a62e8c9b6c2/
  - https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/e7250648cb16d4a497ae8737943bf010ea96d2e6/Defender%20For%20Cloud%20Apps/MaliciousEmailDeliveredInMailbox.md
rules:
  - title: M365 Suspicious Email Delivered
    description: Detects instances where an email identified as malicious or suspicious by Microsoft Defender for Office 365 was delivered.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
    techniques:
      - T1566.001
      - T1566.002
    data_sources:
      - m365
      - audit
  - title: M365 Suspicious Email Delivered to Junk
    description: Detects instances where a flagged email was delivered to the Junk folder.
    platform: sigma
    severity: medium
    tactics:
      - initial-access
    techniques:
      - T1566.001
      - T1566.002
    data_sources:
      - m365
      - audit
rules_count: 2
---

This threat involves malicious or suspicious emails, as identified by Microsoft Defender for Office 365, being delivered to user mailboxes despite the existing security mechanisms. This can occur due to various factors, including misconfigured security policies, sophisticated attacker techniques that evade detection, or delayed signature updates. The delivery of such emails presents a significant risk, as they may contain spearphishing attachments, malicious links, or other harmful content…
