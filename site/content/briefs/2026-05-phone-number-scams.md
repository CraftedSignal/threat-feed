---
title: Phone Number Reuse in Scam Email Campaigns
slug: 2026-05-phone-number-scams
description: Talos has begun tracking phone numbers in emails as indicators of compromise, revealing insights into their reuse in scam campaigns where attackers use API-driven VoIP services for cost-effective operations, rotating phone number blocks to evade security filters, and maximizing reach by recycling numbers across diverse lures.
date: "2026-05-06T10:01:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - email
  - phishing
  - voip
  - scam
vendors:
  - Cisco
  - Virtue
  - Twilio
  - Bandwidth
  - AT&T
  - Verizon
  - RingCentral
  - Sinch
  - NUSO
  - Best Buy
  - McAfee
  - Norton LifeLock
  - PayPal
products:
  - Geek Squad
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://blog.talosintelligence.com/insights-into-the-clustering-and-reuse-of-phone-numbers-in-scam-emails/
iocs:
  - type: email
    value: emails
  - type: phone
    value: phone numbers
ioc_counts:
  email: 1
  phone: 1
rules:
  - title: Detect Email with Phone Number and Brand Impersonation Subject
    description: Detects emails containing phone numbers in the body and subject lines impersonating popular brands.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - email
      - windows
  - title: Detect Email with VoIP Phone Number
    description: Detects emails containing VoIP phone numbers in the body.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - email
      - windows
rules_count: 2
---

Talos has started collecting intelligence around phone numbers within emails as an additional indicator of compromise. Their analysis of scam campaigns between February 26 and March 31, 2026, reveals the prevalence of phone number reuse, especially with VoIP numbers due to their ease of acquisition and difficulty of tracing. Attackers use VoIP providers, particularly CPaaS platforms like Sinch, for rapid, API-driven number provisioning. They rotate through sequential blocks of phone numbers with a median lifespan of 14 days to evade reputation-based security filters. This allows them to maintain operational continuity and project a consistent brand presence. Attackers also recycle phone numbers across diverse lures, including varied subject lines and different attachment formats like HEIC and PDF, to impersonate multiple brands simultaneously, like PayPal, Geek Squad, McAfee and Norton LifeLock.

## Attack Chain

1.  Initial email sent to victim with a lure impersonating a known brand (e.g., PayPal, Geek Squad).
2.  The email contains a phone number, often a VoIP number, directing the recipient to call.
3.  Victim calls the provided phone number.
4.  Attacker, posing as customer service or technical support, engages the victim in a real-time conversation.
5.  Attacker manipulates the victim into disclosing sensitive information (e.g., financial details, personal data).
6.  Alternatively, the attacker persuades the victim to install malicious software under the guise of legitimate software updates or security tools.
7.  If malware is installed, attacker gains remote access or control over the victim's device.
8.  Attacker uses stolen information for financial gain or further malicious activities.

## Impact

Scam campaigns utilizing phone numbers in emails can lead to significant financial losses and data breaches for victims. The abuse of VoIP services enables attackers to operate cost-effectively and at scale.  While the exact number of victims is not specified, the report highlights the widespread use of this tactic and the potential for substantial impact across various sectors, targeting brands like PayPal, Geek Squad (Best Buy), McAfee, and Norton LifeLock. If the attack succeeds, victims may experience identity theft, financial fraud, and compromise of their devices.

## Recommendation

*   Monitor email traffic for the presence of phone numbers, particularly those associated with VoIP providers like Sinch, using the IOCs provided.
*   Implement the provided Sigma rules to detect suspicious email patterns and phone number usage.
*   Block known malicious phone numbers identified in scam campaigns at the telecom provider level.
*   Educate users about Telephone-Oriented Attack Delivery (TOAD) and the risks associated with calling phone numbers provided in unsolicited emails.
