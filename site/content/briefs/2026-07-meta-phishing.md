---
title: Meta Business Manager Phishing Campaign Leveraging Legitimate Services
slug: 2026-07-meta-phishing
description: A threat actor group is actively conducting a phishing campaign since November 2025, abusing Meta's legitimate Business Account Manager service to send emails from noreply@business.facebook.com containing malicious Google Sites URLs that redirect to sophisticated phishing pages, ultimately aiming to steal Meta account credentials, MFA codes, personal and business contact information, and identification documents from targeted businesses, with recent evolutions including a Facebook Messenger chatbot and exfiltration to Telegram.
date: "2026-07-09T20:28:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - credential-theft
  - cloud
  - email-security
vendors:
  - Meta
  - Google
  - Telegram
products:
  - Meta Business Account Manager Service
  - Facebook
  - Instagram
  - Facebook Messenger
  - Google Sites
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Huntress is tracking a threat actor who has figured out how to manipulate a legitimate service offering from Meta to send a spam lure email that passes validation.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The phishing group... modified their phishing lure to incorporate a chatbot... and began sending credentials to a private Telegram channel.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The phishing campaign appears to target businesses and attempts to capture credentials, MFA codes, business and personal phone numbers, email addresses, and an image of the target's ID or passport.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: 'api.goautolink[.]com: Earlier exfiltration domain used to receive stolen victim data.'
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: began sending credentials to a private Telegram channel.
    confidence_band: high
references:
  - https://www.huntress.com/blog/meta-business-manager-phishing
iocs:
  - type: email
    value: noreply@business.facebook.com
  - type: domain
    value: aussiecleaningservices[.]com
  - type: domain
    value: api.goautolink[.]com
  - type: domain
    value: sw[.]run
  - type: domain
    value: businesshelpcenterpageid563252.netlify[.]app
ioc_counts:
  domain: 4
  email: 1
rules:
  - title: Detect Access to Known Meta Phishing Domains
    description: Detects user access attempts to known phishing domains and URLs used in the Meta Business Manager phishing campaign.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566.002
    data_sources:
      - webserver
rules_count: 1
---

Since late 2025, an unknown threat actor group has been executing an evolving phishing campaign primarily targeting businesses that utilize Meta platforms. The attackers ingeniously abuse Meta's legitimate Business Account Manager service to dispatch initial lure emails, which deceptively originate from the trusted address `noreply@business.facebook.com`, bypassing traditional email validation mechanisms. The campaign, which intensified in June 2026 with new infrastructure, directs victims via embedded URLs (frequently Google Sites pages such as `sites.google[.]com/view/profile1012`) to sophisticated phishing pages (e.g., `aussiecleaningservices[.]com`, `businesshelpcenterpageid563252.netlify[.]app`). These pages are meticulously crafted to impersonate Meta's interfaces, aiming to harvest sensitive information including Meta account credentials, multi-factor authentication (MFA) codes, business and personal phone numbers, email addresses, and even images of government-issued IDs or passports. Stolen data is then exfiltrated to attacker-controlled domains like `api.goautolink[.]com` or private Telegram channels, marking a significant credential theft and data exfiltration operation.

## Attack Chain

1. **Initial Access / Lure Construction:** Threat actors abuse Meta's Business Account Manager service to send phishing emails that appear to originate from the legitimate address `noreply@business.facebook.com`.
2. **Delivery:** These carefully crafted emails are sent to targeted businesses, containing a malicious URL embedded within the email text.
3. **Redirection:** The malicious URL initially points to a Google Sites page (e.g., `sites.google[.]com/view/profile1012`), acting as an intermediate redirector to evade immediate detection.
4. **Phishing Page Hosting:** Victims are then redirected from the Google Sites page to sophisticated phishing landing pages, often hosted on services like Netlify (e.g., `businesshelpcenterpageid563252.netlify[.]app`) or attacker-controlled domains (e.g., `aussiecleaningservices[.]com`).
5. **Credential & Data Collection:** The phishing pages are designed to mimic legitimate Meta interfaces, prompting victims to enter Meta account credentials, MFA codes, business and personal phone numbers, email addresses, and in some cases, an image of their ID or passport.
6. **Exfiltration:** Stolen credentials and personal data are then exfiltrated to attacker-controlled infrastructure, such as `api.goautolink[.]com`, or directly sent to private Telegram channels for collection.
7. **Evolving Tactics:** Newer variants of the attack incorporate a chatbot accessible via Facebook Messenger, which the phishing lure directs users to interact with, indicating continuous refinement of the social engineering tactics.

## Impact

The primary impact of this campaign is the widespread compromise of Meta Business accounts through credential and MFA code theft. Successful attacks lead to unauthorized access to critical business assets on Facebook and Instagram, potential financial fraud, and further exploitation through business email compromise (BEC). The collection of personal phone numbers, email addresses, and identification documents exposes victims to identity theft and further targeted social engineering. The campaign targets businesses, making the potential for financial and reputational damage significant if attackers gain control of their social media presence or leverage stolen data for broader organizational access.

## Recommendation

* Block the IOC domains: `aussiecleaningservices[.]com`, `api.goautolink[.]com`, `sw[.]run`, `businesshelpcenterpageid563252.netlify[.]app` at your organization's DNS resolvers and web proxies.
* Block the IOC URL `sites.google[.]com/view/profile1012` at your web proxies and network firewalls.
* Deploy the Sigma rule "Detect Access to Known Meta Phishing Domains" to your SIEM and configure alerts for detected access attempts.
* Implement robust email security controls to identify and flag suspicious URLs, even those originating from seemingly legitimate senders like `noreply@business.facebook.com`, especially when they link to external redirection services.
