---
title: Large-Scale Smishing Campaign Impersonating Transport Authorities
slug: 2026-04-operation-road-trap
description: A smishing campaign has been active since December 2025, targeting drivers in 12 countries with fraudulent text messages impersonating transport authorities, toll operators, and parking services, resulting in over 79,000 fraudulent messages sent as of April 2026.
date: "2026-04-29T12:55:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - smishing
  - fraud
  - social-engineering
vendors:
  - Bitdefender
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.bitdefender.com/en/us/blog/labs/operation-road-trap
rules:
  - title: SMS Keyword Detection
    description: Detects SMS messages containing keywords associated with toll and parking scams.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - proxy
      - linux
  - title: Detect Newly Registered Domains Similar to Toll Services
    description: Detects connections to newly registered domains that closely resemble legitimate toll or parking service domains, potentially indicating a phishing site.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - dns_query
      - windows
rules_count: 2
---

Since December 2025, a large-scale smishing campaign has been targeting drivers across 12 countries. This operation, dubbed "Operation Road Trap" by Bitdefender Labs, involves sending fraudulent text messages to mobile users. The messages impersonate transport authorities, toll operators, and parking services. The campaign remains active as of April 2026, with researchers tracking the operation and observing the distribution of over 79,000 fraudulent messages. This poses a significant threat to individuals who may be tricked into divulging personal or financial information.

## Attack Chain

1.  The attacker identifies potential victims, likely targeting drivers in specific regions based on publicly available information or purchased lists.
2.  The attacker crafts a fraudulent text message impersonating a transport authority, toll operator, or parking service. The message typically contains a link to a malicious website.
3.  The attacker sends the smishing message to the victim's mobile phone via SMS.
4.  The victim receives the message and, believing it to be legitimate, clicks on the embedded link.
5.  The link redirects the victim to a fake website that mimics the official website of the impersonated organization.
6.  The website prompts the victim to enter personal information such as their name, address, phone number, credit card details, or banking credentials.
7.  The victim unknowingly enters their sensitive information on the fraudulent website, which is then captured by the attacker.
8.  The attacker uses the stolen information for financial fraud, identity theft, or other malicious purposes.

## Impact

This smishing campaign, active since December 2025 and still ongoing in April 2026, has affected over 79,000 individuals across 12 countries. Victims who fall for the scam risk having their personal and financial information stolen, potentially leading to financial losses, identity theft, and other forms of fraud. The broad scope of the campaign suggests a significant operational capacity on the part of the attackers.

## Recommendation

*   Deploy the Sigma rule for SMS keyword detection to identify potentially malicious text messages based on keywords such as "toll," "parking," or "overdue" referencing `rules/sms_keyword_detection`.
*   Monitor web traffic for connections to newly registered domains that are similar to legitimate toll or parking services. Block known malicious domains at the DNS resolver.
*   Educate users about smishing tactics and advise them to be cautious of unsolicited text messages requesting personal information.
