---
title: Threat Actors Spoofing FIFA Websites in Advance of the 2026 World Cup
slug: 2026-05-fifa-spoofing
description: Cyber threat actors are conducting spoofing attacks against FIFA websites in advance of the 2026 FIFA World Cup to steal personal information and facilitate monetary scams.
date: "2026-05-27T18:24:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - fifa
  - spoofing
  - phishing
  - typo-squatting
vendors:
  - Fédération Internationale de Football Association (FIFA)
products:
  - fifa.com
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1583
    technique_name: Obtain Capabilities
references:
  - https://www.ic3.gov/PSA/2026/PSA260527
iocs:
  - type: domain
    value: www.fifa[.]cab
  - type: domain
    value: www.fifa[.]pink
  - type: domain
    value: www.fifa[.]blue
  - type: domain
    value: www.fifa[.]pub
  - type: domain
    value: FIFA[.]city
  - type: domain
    value: Fifa[.]bio
  - type: domain
    value: fifa[.]beer
  - type: domain
    value: fifa[.]click
  - type: domain
    value: fifa[.]cam
  - type: domain
    value: fifa[.]ceo
  - type: domain
    value: fifa[.]help
  - type: domain
    value: filfa[.]org
  - type: domain
    value: fifa-online[.]com
  - type: domain
    value: fifa-2026[.]xyz
  - type: domain
    value: jobs-fifa[.]com
  - type: domain
    value: fifa-hr[.]com
  - type: domain
    value: fifa-careerhub[.]com
  - type: domain
    value: fifaworldcup-careers[.]com
  - type: domain
    value: fifa-hiring[.]com
  - type: domain
    value: fifahiring[.]com
  - type: domain
    value: fifa-ticket[.]live
  - type: domain
    value: fifastore.us[.]com
  - type: domain
    value: fifaworldcup26[.]sale
  - type: domain
    value: fifaworldcup26.xcover-staging[.]com
  - type: domain
    value: worldcup2026-tickets.com[.]mx
  - type: domain
    value: worldcup26ticket[.]com
  - type: domain
    value: 2026fifaworldcuptickets[.]online
  - type: domain
    value: fwc2026[.]net
  - type: domain
    value: fwc2026.web[.]app
  - type: domain
    value: www.fifa2026p[.]com
  - type: domain
    value: fifa2026fworldcup[.]com
  - type: domain
    value: wvvw-fifa[.]com
  - type: domain
    value: ww-fifa[.]com
  - type: domain
    value: fifa-com[.]com
  - type: domain
    value: www.fifa-com[.]services
  - type: domain
    value: quiniela-fifa-2026.pages[.]dev
ioc_counts:
  domain: 36
rules:
  - title: Detect Typo-Squatting of FIFA Domains
    description: Detects connections to newly registered domains that are similar to 'fifa.com', indicating potential typo-squatting attacks.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1583.006
    data_sources:
      - dns_query
      - windows
  - title: Detect Access to Newly Registered FIFA-Related Domains
    description: Detects access to newly registered domains containing 'fifa' based on domain age to identify potential spoofing attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1583.006
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The FBI has issued a public service announcement warning of cyber threat actors conducting spoofing attacks against the Fédération Internationale de Football Association (FIFA) website in anticipation of the 2026 FIFA World Cup. These actors create deceptive versions of the legitimate FIFA website (www.fifa.com) with the goal of tricking users into believing they're interacting with the official brand. The spoofed websites are designed to collect personally identifiable information (PII) entered by users, including names, home addresses, phone numbers, email addresses, and banking information. The threat actors also aim to sell fake World Cup tickets and hospitality products and possibly facilitate other malicious activities. The FBI has identified multiple domains already spoofing the legitimate FIFA website and anticipates additional fake domains will be created leading up to and throughout the 2026 World Cup.

## Attack Chain

1.  The attacker registers a domain name that closely resembles the legitimate FIFA website (www.fifa.com), often using typos or alternative top-level domains (e.g., fiffa[.]com, fifa[.]org).
2.  The attacker sets up a website on the spoofed domain that mimics the look and feel of the official FIFA website, including branding, logos, and content.
3.  The attacker promotes the spoofed website through various means, such as search engine optimization (SEO) or social media, to attract unsuspecting users.
4.  A user visits the spoofed website, believing it to be the legitimate FIFA site.
5.  The user is prompted to enter personal information, such as name, address, phone number, email, and banking details, to register for an account, purchase tickets, or apply for a job.
6.  The attacker collects the user's PII entered into the spoofed site.
7.  The attacker uses the stolen PII to create new accounts in the victim's name, commit identity theft, or sell the information to other malicious actors.
8.  The attacker attempts to sell fake World Cup tickets and hospitality products to the victim, potentially leading to financial loss.

## Impact

The spoofed FIFA websites can lead to significant financial and personal information loss for victims. Threat actors can collect PII, create fraudulent accounts, and sell fake World Cup tickets and hospitality products. The number of victims is currently unknown, but the FBI anticipates that these attacks will increase leading up to the 2026 FIFA World Cup. These attacks target anyone attempting to access FIFA's website for information, tickets, or employment opportunities. A successful attack can result in identity theft, financial fraud, and reputational damage for the victims.

## Recommendation

*   When navigating to FIFA's official website, type fifa.com directly into the address bar, as recommended by the FBI, rather than using a search engine.
*   Implement a domain reputation feed to identify and block access to newly registered or suspicious domains similar to the IOCs in this brief.
*   Monitor network traffic for connections to the IOCs listed in this brief, and block them at the firewall or proxy level.
*   Deploy the Sigma rule to detect potential typo-squatting attempts on FIFA domains.
*   Educate users about the dangers of typo-squatting and phishing, emphasizing the importance of verifying website URLs and avoiding suspicious links.
