---
brief_id: brief-2026-10-29-prediction-market-fraud
event_id: brief-2026-10-29-prediction-market-fraud
revision: 1
activity_at: "2026-10-29T18:33:32Z"
title: Russian Traffer Teams Exploiting Prediction Markets via Turnkey Fraud Infrastructure
slug: 2026-10-prediction-market-fraud
description: Russian-language traffer teams, including AtlasCore, PolyFucked, and Magnetic Team, are operating affiliate-fraud networks that deploy simulated prediction market websites to steal cryptocurrency and sensitive identity information.
date: "2026-10-29T18:33:32Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - fraud
  - financial-crime
  - prediction-market
  - cryptocurrency
  - ai-assisted-threats
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The services combine convincing prediction-market interfaces with established fraud mechanisms designed to manipulate victims.
    confidence_band: high
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1583
    technique_name: Acquire Infrastructure
    evidence: AtlasCore, PolyFucked, and Magnetic Team supply affiliates with simulated prediction-market websites, administrative panels, payment infrastructure, and promotional support.
    confidence_band: high
references:
  - https://www.recordedfuture.com/research/prediction-markets-traffer-teams
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  hunt_leads:
    - lead: Identification of traffic to suspected fake prediction market domains
      technique_id: T1583
      data_needed:
        - DNS query logs
        - Web proxy / Secure Web Gateway logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Insikt Group identified over 100 unique domains and subdomains associated with AtlasCore, PolyFucked, and Magnetic Team.
  mitigation_plan:
    - priority: short_term
      action: Enforce web-filtering policies to block access to suspicious, newly registered domains mimicking financial services.
      owner: IT Operations
      addresses: Turnkey fraud platforms
      evidence: Teams provide websites, administrative panels, and crypto payment infrastructure.
---

Since early 2026, Russian-language "traffer" teams have expanded their affiliate-fraud operations to mimic legitimate prediction markets such as PolyMarket and Kalshi. Teams like AtlasCore, PolyFucked, and Magnetic Team provide turnkey platforms that include simulated trading interfaces, cryptocurrency payment processing, and administrative panels for affiliates to manage victims. These platforms employ technical controls to ensure victim funds are stolen, including fabricated market activity, forced trading losses, and automated withdrawal blocking. The use of AI is pervasive across these operations, assisting in the development of fraudulent platforms, social engineering content, and victim engagement.

## Attack Chain

1. Infrastructure Acquisition: Affiliates deploy pre-built fraud websites and administrative backends provided by traffer teams.
2. Promotion: Affiliates use AI-generated promotional content, including synthetic influencers, to drive traffic to fraudulent sites.
3. Victim Onboarding: Victims are lured to sites mimicking legitimate prediction markets, where they are prompted to deposit cryptocurrency.
4. Platform Manipulation: Operators utilize administrative panels to manufacture the illusion of legitimate market activity and force trading losses.
5. Information Collection: Sites capture sensitive identity and financial information from victims under the guise of verification.
6. Financial Exfiltration: Victims are denied fund withdrawals through artificial restrictions, fees, or controlled platform outcomes.

## Impact

Threat actor reports claim significant financial activity, with AtlasCore citing approximately $10.97 million in deposits between May and September 2026, and PolyFucked reporting $2.4 million in quarterly turnover. These figures remain unverified. The fraud results in direct financial loss via stolen deposits and potential identity theft.

## Recommendation

- Implement proactive domain monitoring to identify typosquatted or imitation domains targeting prediction market brands.
- Enhance user awareness training to highlight the indicators of fraudulent financial platforms, such as artificial withdrawal restrictions and high-pressure investment tactics.
- Review and block suspicious traffic patterns originating from infrastructure associated with known "traffer" affiliate networks when identified.
- Establish enhanced monitoring for cryptocurrency-related transactions on endpoints that may interact with these fraudulent platforms.
