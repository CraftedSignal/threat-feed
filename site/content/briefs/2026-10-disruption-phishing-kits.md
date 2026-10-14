---
title: Disruption of High-Volume Phishing Ecosystem Targeting Japanese Entities
slug: 2026-10-disruption-phishing-kits
description: A coordinated disruption action targeting the CoGUI, CoAceV, and CoFish_Ws phishing kits has impacted an ecosystem responsible for billions of malicious messages harvesting credentials and payment data from global organizations.
date: "2026-10-14T16:44:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - credential-harvesting
  - financial-fraud
  - credential-access
  - email-threats
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Campaigns distribute hundreds of millions of messages containing URLs that lead to landing pages that masquerade as login or payment portals.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: Phishing kits impersonate well-known companies in order to steal usernames, passwords, and payment data such as credit card information.
    confidence_band: high
---

In October 2026, a collaborative disruption effort involving Microsoft, Proofpoint, and other international partners successfully targeted a prominent Chinese-language phishing ecosystem. This operation addressed the infrastructure of three major phishing kits: CoGUI, CoAceV, and CoFish_Ws, alongside broader ecosystem enablers identified as YAM Store and Iron Man. These actors have been responsible for distributing over one billion malicious messages targeting more than 75,000 organizations globally since January 2026. The kits primarily focus on Japanese consumer and financial brands, using highly dynamic infrastructure to steal usernames, passwords, and credit card information. The disruption, supported by a civil lawsuit in the U.S. District Court for the Southern District of Florida, involved the seizure of numerous domains used to manage these campaigns.

## Attack Chain

1. Threat actors procure and manage large-scale, dynamic infrastructure consisting of thousands of frequently rotated domains.
2. Attackers develop and deploy sophisticated phishing kits (CoGUI, CoAceV, CoFish_Ws) capable of impersonating 66+ major consumer and financial brands.
3. High-volume email campaigns are distributed to targets, often leveraging themes of financial information, credit card details, or shipping notifications.
4. Links within emails direct potential victims through automated filters or CAPTCHA pages, which serve as decoys to evade security sandbox detection.
5. Victims are redirected to malicious landing pages masquerading as legitimate login or payment portals for the impersonated companies.
6. Victim input, including sensitive credentials and payment data, is captured by the phishing kit and exfiltrated to actor-controlled infrastructure.
7. Captured data is used for unauthorized financial gain, including potential investment fraud and illicit account takeovers.

## Impact

The phishing operation has targeted over 75,000 organizations worldwide since the beginning of 2026, with a primary focus on the Financial Services and Healthcare sectors. The impersonation of Japanese brands such as PayPay, MyJCB, and Rakuten has resulted in significant financial and reputational damage to victims. Beyond the immediate theft of credentials, evidence suggests the collected data may have been used to manipulate Chinese stock markets, illustrating the breadth of the threat actors' objectives.

## Recommendation

Prioritize the following actions to secure environments against the remnants of this ecosystem:

* Implement robust URL filtering and proxy solutions to block traffic to domains exhibiting patterns associated with the identified kits (e.g., dynamic, newly registered domains mimicking popular financial portals).
* Monitor for high-volume email traffic originating from suspicious domains and implement DMARC, SPF, and DKIM to mitigate domain impersonation.
* Train users on verifying landing page URLs for financial services, as these campaigns focus heavily on credential harvesting via masqueraded portals.
* Audit for any successful authentication anomalies or unusual financial transactions associated with employees, specifically for those dealing with Japanese or international consumer finance accounts.
