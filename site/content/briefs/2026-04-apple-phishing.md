---
title: Apple Account Notification Phishing Campaign
slug: 2026-04-apple-phishing
description: A phishing campaign is abusing legitimate Apple account change notifications to deliver fake iPhone purchase scams, tricking users into calling malicious support numbers.
date: "2026-04-19T16:03:01Z"
type: advisory
types:
  - advisory
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
iocs:
  - type: email
    value: hxfedna24005@icloud.com
  - type: email
    value: appleid@id.apple.com
  - type: email
    value: uatdsasadmin@email.apple.com
  - type: ip
    value: 17.111.110.47
  - type: phone
    value: "18023530761"
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

A phishing campaign is underway that abuses Apple's account change notification system. Threat actors are inserting phishing messages into the first and last name fields of Apple ID accounts. By modifying the account's shipping information, they trigger legitimate Apple security alerts, which then embed the malicious message within the email body. The emails appear to originate from appleid@id.apple.com and pass SPF, DKIM, and DMARC checks, making them more likely to bypass spam filters. This campaign is designed to trick recipients into believing their accounts have been used for fraudulent purchases, scaring them into calling a scammer's "support" number.

## Attack Chain

1.  The attacker creates an Apple ID using a burner email address.
2.  The attacker enters a phishing lure (e.g., "Dear User 899 USD iPhone Purchase Via Pay-Pal To Cancel") split across the first and last name fields in the Apple ID profile, as these fields have character limits.
3.  The attacker modifies the account's shipping information.
4.  This triggers an Apple account profile change notification email.
5.  Apple sends a legitimate security alert notifying the user of the change, embedding the attacker-controlled first and last name fields within the email body. The email originates from appleid@id.apple.com.
6.  The recipient receives the email, which appears legitimate and contains a phishing message and a callback number (e.g., 18023530761).
7.  The recipient, believing their account has been compromised, calls the provided number.
8.  The scammers attempt to convince the victim that their account has been compromised and may instruct them to install remote access software or provide financial information to "resolve" the issue, leading to financial theft.

## Impact

Successful attacks can lead to financial theft, malware deployment, or data theft. Victims who call the provided number are at risk of being coerced into providing sensitive information or installing remote access software, giving the attackers full control over their devices and accounts. The specific number of victims is currently unknown, but the campaign's use of legitimate Apple infrastructure increases its potential reach and impact.

## Recommendation

*   Deploy the Sigma rule detecting emails originating from Apple infrastructure (appleid@id.apple.com) containing suspicious phone numbers to your SIEM.
*   Monitor for emails originating from `appleid@id.apple.com` that contain phone numbers in the email body and consider blocking the identified number `18023530761`.
*   Educate users to treat unexpected account alerts claiming purchases or urging them to call support numbers with extreme caution, especially if they did not initiate any recent changes.
*   Review email gateway logs for emails originating from `appleid@id.apple.com` and `uatdsasadmin@email.apple.com`.
