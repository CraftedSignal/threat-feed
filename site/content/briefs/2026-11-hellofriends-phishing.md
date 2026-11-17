---
brief_id: brief-2026-11-17-hellofriends-phishing
event_id: brief-2026-11-17-hellofriends-phishing
revision: 1
activity_at: "2026-11-17T15:47:00Z"
title: 'HelloFriends Campaign: Phishing Attacks Targeting US Logistics Carriers'
slug: 2026-11-hellofriends-phishing
description: The HelloFriends campaign uses sophisticated phishing impersonating the FMCSA to harvest PII and fuel card credentials from US trucking companies, exfiltrating data via Vercel-hosted infrastructure to Telegram.
date: "2026-11-17T15:47:00Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://any.run/cybersecurity-blog/us-logistics-cyber-threats-3-campaigns/
  observed_at: "2026-11-17T15:47:00Z"
  confidence: high
source_assessment:
  reliability: C
  credibility: "2"
  rating: C2
  likelihood: likely
vendors:
  - Comdata
  - EFS
  - Fleet One
  - Relay
  - WEX
products:
  - Motus
  - SAFER
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The campaign begins with phishing emails impersonating the Federal Motor Carrier Safety Administration (FMCSA).
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
    evidence: In observed Relay and Comdata flows, the first password is deliberately rejected, prompting victims to enter a second password before being asked for an SMS or six-digit authentication code.
references:
  - https://any.run/cybersecurity-blog/us-logistics-cyber-threats-3-campaigns/
iocs:
  - type: domain
    value: dotcompanyinfo.com
  - type: domain
    value: dot.fmcsa.saferprofilereview.info
  - type: domain
    value: motus.relayconsolidation.online
  - type: domain
    value: motus.iconnectdataconsolidation.online
ioc_counts:
  domain: 4
rules:
  - title: HelloFriends Phishing Exfiltration
    description: Detects outbound connections to Vercel-hosted APIs used by HelloFriends for data exfiltration.
    platform: sigma
    severity: medium
    techniques:
      - T1566
    data_sources:
      - network_connection
rules_count: 1
---

## Overview
The HelloFriends campaign targets US trucking and logistics entities through fraudulent portals mimicking legitimate carrier verification services like SAFER and Motus. Attackers utilize phishing emails impersonating the Federal Motor Carrier Safety Administration (FMCSA), often incorporating the recipient's actual USDOT number to increase credibility. The operation is designed to harvest extensive sensitive information, including Social Security numbers (SSN), Employer Identification Numbers (EIN), and eventually, multi-factor authentication codes for fleet fuel management accounts such as Relay, Comdata, WEX, EFS, and Fleet One.

## Attack Chain
1. Initial access via phishing emails masquerading as official FMCSA communications.
2. Redirection to fraudulent carrier verification portals (e.g., SAFER or Motus clones).
3. Collection of PII and business identifiers (SSN, EIN, contact info).
4. Enforcement of a mandatory $300 administrative fee for status reactivation.
5. Prompt for fleet fuel provider credentials (e.g., Relay or Comdata).
6. Deliberate rejection of initial password entries to solicit secondary authentication and SMS or six-digit MFA codes.
7. Exfiltration of harvested credentials and PII through server-side endpoints on Vercel-hosted Next.js applications to Telegram.

## Impact
Successful exploitation leads to the theft of PII, business credentials, and fuel-card access, creating risks of account takeover and financial fraud.

## Recommendation
- Audit and block traffic to Vercel-hosted subdomains that exhibit anomalous patterns matching known HelloFriends infrastructure.
- Implement strict email filtering for domains mimicking FMCSA communication, particularly those involving unauthorized sender domains like dotcompanyinfo.com.
- Educate logistics staff on the fraudulent nature of 'urgent' USDOT reactivation requests and suspicious demands for administrative fees through unverified portals.
- Monitor for unauthorized account access attempts targeting fleet fuel management services (Relay, Comdata, WEX, EFS, Fleet One).
