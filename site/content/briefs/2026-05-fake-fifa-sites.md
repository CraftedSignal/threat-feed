---
title: Fake FIFA World Cup Websites Stealing Credentials and Funds
slug: 2026-05-fake-fifa-sites
description: Fake FIFA World Cup websites are impersonating official ticket and merchandise sales to steal money and personal data from soccer fans through deceptive registration and payment processes.
date: "2026-05-23T06:09:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - credential-theft
  - scams
  - fifa
  - world-cup
vendors:
  - FIFA
  - Qatar Airways
  - ESET
products:
  - World Cup tickets
  - World Cup merchandise
  - fifa.com/tickets
  - fifa.com/hospitality
  - Qatar Airways travel packages
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1598
    technique_name: Phishing for Information
references:
  - https://www.welivesecurity.com/en/cybersecurity/foul-play-fake-fifa-world-cup-websites-tickets/
iocs:
  - type: url
    value: https://***fifa26[.]shop
  - type: url
    value: https://****26-fifa[.]com
ioc_counts:
  url: 2
rules:
  - title: Detect Fake FIFA Website Registration Page
    description: Detects access to fake FIFA website registration pages potentially used for credential theft.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1598
    data_sources:
      - webserver
  - title: Detect Fake FIFA Website Payment Page
    description: Detects access to fake FIFA website payment pages potentially used for financial theft.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1598
    data_sources:
      - webserver
rules_count: 2
---

ESET researchers have uncovered multiple fake FIFA World Cup websites designed to deceive soccer fans seeking tickets and merchandise. These websites mimic the official FIFA and World Cup sites, enticing users to register and make purchases through fraudulent payment flows. The attackers utilize tactics such as typosquatting, where domain names closely resemble the legitimate ones, and copying the official FIFA website's look and feel to enhance credibility. The campaign targets individuals eager to secure tickets and merchandise for the 2026 FIFA World Cup, exploiting their enthusiasm and impatience. The fake sites aim to steal financial and identity data, including names, email addresses, phone numbers, and passwords.

## Attack Chain

1.  Victims are lured to fake FIFA websites through sponsored search results, social media ads, or forwarded links.
2.  The fake website uses a domain name similar to the official FIFA site, employing typosquatting (e.g., ***fifa26[.]shop).
3.  The website replicates the look and feel of the official FIFA site, including colors, layout, and navigation.
4.  Users are prompted to register, providing personal information such as name, email address, and phone number.
5.  The fake website offers tickets and merchandise for purchase, allowing users to add items to a shopping cart.
6.  Users are directed to a payment page where they enter their credit card details.
7.  The entered payment information is stolen by the attackers.
8.  Victims lose money and have their personal and financial data compromised.

## Impact

The fake FIFA websites lead to financial losses for victims who enter their credit card details. Stolen personal data, including names, email addresses, phone numbers, and reused passwords, can be used for identity theft, financial fraud, and further attacks on other accounts. The campaign targets soccer fans worldwide, aiming to capitalize on the high demand for World Cup tickets and merchandise. If successful, attackers can gain access to victims' sensitive information, leading to significant financial and personal harm.

## Recommendation

*   Directly type the official FIFA website address (FIFA.com) into your browser to avoid clicking on potentially malicious links from ads or social media posts (Reference: FIFA official website).
*   Closely examine domain names for typosquatting attempts (e.g., extra characters, odd endings) before entering any information (Reference: ***fifa26[.]shop and ****26-fifa[.]com).
*   Deploy the Sigma rule `Detect Fake FIFA Website Registration Page` to identify suspicious registration pages (Reference: rule).
*   Deploy the Sigma rule `Detect Fake FIFA Website Payment Page` to identify suspicious payment pages (Reference: rule).
*   Use strong, unique passwords for all accounts and enable two-factor authentication to protect against credential reuse (Reference: Overview).
