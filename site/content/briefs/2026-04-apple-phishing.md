---
title: Apple Account Notification Phishing Campaign
slug: 2026-04-apple-phishing
description: A phishing campaign is abusing legitimate Apple account change notifications to deliver fake iPhone purchase scams, tricking users into calling malicious support numbers.
date: "2026-04-19T16:03:01Z"
severities:
  - high
tags:
  - apple
  - phishing
  - callback phishing
  - email
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.bleepingcomputer.com/news/security/apple-account-change-alerts-abused-to-send-phishing-emails/
ioc_counts:
  email: 3
  ip: 1
  phone: 1
rules:
  - title: Detect Apple Email with Phone Number
    description: Detects emails from Apple infrastructure containing phone numbers, indicative of callback phishing attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - email
      - mailserver
  - title: Detect Apple Email infrastructure IP
    description: Detects emails from Apple infrastructure IP addresses containing phone numbers, indicative of callback phishing attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - email
      - mailserver
rules_count: 2
---

A phishing campaign is underway that abuses Apple's account change notification system. Threat actors are inserting phishing messages into the first and last name fields of Apple ID accounts. By modifying the account's shipping information, they trigger legitimate Apple security alerts, which then embed the malicious message within the email body. The emails appear to originate from appleid@id.apple.com and pass SPF, DKIM, and DMARC checks, making them more likely to bypass spam filters. This…
