---
title: Iran's MOIS Expands Handala Brand to Physical Threat Operations
slug: 2026-06-handala-physical-threats
description: Iran's MOIS has broadened the Handala brand to encompass physical threat operations, recruiting proxies to conduct attacks, espionage, and sabotage against US and Israeli interests, amplifying both cyber and physical threats.
date: "2026-06-02T13:57:08Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - MOIS
tags:
  - iran
  - mois
  - handala
  - physical-threat
  - influence-operations
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.recordedfuture.com/research/iran-handala-physical-threats
rules:
  - title: Detect Handala Related Keywords in Social Media
    description: Detects mentions of 'Handala Popular Resistance Front' or related keywords in social media posts, potentially indicating recruitment or propaganda activity.
    platform: sigma
    severity: low
    techniques:
      - T1566
    data_sources:
      - webserver
rules_count: 1
---

Iran's Ministry of Intelligence (MOIS) has expanded the use of its "Handala" brand to include external physical and influence operations targeting US and Israeli interests. The Handala Hack Team, referring to itself as the "Handala Popular Resistance Front" (HPRF), shares online activities with three previously identified influence operations networks. These groups are now attributed to MOIS, with varying degrees of confidence. The administrators solicit individuals to conduct physical attacks and espionage targeting US and Israeli entities on behalf of Iranian intelligence agencies, for financial reward. MOIS seeks to leverage Handala's global recognition to amplify its solicitation efforts.

## Attack Chain

1. MOIS establishes the "Handala Popular Resistance Front" (HPRF) as a branded persona.
2. HPRF and associated influence networks solicit individuals for physical attacks and espionage against US and Israeli entities.
3. Recruits are offered financial rewards for their participation in the operations.
4. Recruits conduct reconnaissance on targeted individuals, facilities, or organizations.
5. Recruits plan and execute physical attacks, espionage, or sabotage.
6. HPRF provides operational guidance and potential resources to the recruited individuals.
7. Successful operations are publicized to amplify the Handala brand.
8. MOIS leverages the increased brand recognition to attract more recruits for future operations.

## Impact

MOIS's coordination of cyber, physical, and influence operations under the Handala brand amplifies threats to targeted individuals and facilities. Handala-linked physical threat actors could leverage the brand's recognition to recruit individuals for targeted violent attacks, espionage, sabotage, or other physical threat activities. This entails heightened risks for US and Israeli law enforcement, military, and intelligence agencies and their personnel, in addition to energy, transportation, and research organizations operating in the region.

## Recommendation

*   Monitor social media and online forums for mentions of the "Handala Popular Resistance Front" to identify potential recruitment activities (content).
*   Implement enhanced security measures at US and Israeli law enforcement, military, and intelligence facilities (Impact).
*   Establish threat hunting for individuals expressing interest in conducting attacks, espionage, or sabotage against US and Israeli interests (Attack Chain).
