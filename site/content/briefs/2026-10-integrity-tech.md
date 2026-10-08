---
title: Integrity Technology Group Enabling Global Cyber Espionage
slug: 2026-10-integrity-tech
description: The NCSC and international partners have exposed Integrity Technology Group for facilitating global cyber espionage campaigns through AI-powered scanning, large-scale botnets, and manual network exploitation.
date: "2026-10-08T19:38:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cyber-espionage
  - threat-intel
  - china
  - botnet
  - ai-enabled
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
    evidence: Malicious cyber actors, enabled by Integrity Tech, are uniquely using AI tools, such as automated scanning, alongside large-scale botnets and manual exploitation techniques.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588
    technique_name: Obtain Capabilities
    evidence: The company employs individuals who support a range of malicious cyber activities and contribute to the wider Chinese cyber ecosystem, including developing tools for use and sale, acquiring and hosting infrastructure.
    confidence_band: high
references:
  - https://www.ncsc.gov.uk/news/china-linked-actors-called-out-by-uk-and-international-partners-for-targeting-sensitive-data
  - https://www.ic3.gov/CSA/2026/261008.pdf
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Review and implement mitigation guidance from the joint FBI advisory (IC3-2026-1008).
      owner: SOC
      due: 48h
      evidence: The advisory highlights that organisations are being urged to understand the threat and techniques used by these cyber actors.
  hunt_leads:
    - lead: Monitor for anomalous outbound traffic patterns consistent with botnet signaling.
      technique_id: T1071
      data_needed:
        - Netflow
        - Proxy logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Integrity Tech as the operator of a substantial botnet, where a network of internet-connected devices are infected with malware.
---

The UK's National Cyber Security Centre (NCSC), in coordination with international partners from six countries, has publicly exposed Integrity Technology Group (Integrity Tech), a China-based company with ties to the Chinese government. Integrity Tech is identified as a key facilitator within the broader Chinese cyber ecosystem, providing technical infrastructure and tools that enable malicious cyber actors to conduct global espionage. The company employs personnel tasked with developing exploit tools, acquiring and hosting command-and-control infrastructure, and conducting manual network compromises.

Their operations are closely linked to high-profile threat campaigns previously tracked as Flax Typhoon, Ethereal Panda, and Red Juliett. The advisory highlights the entity's use of AI-enabled automated scanning tools and large-scale botnets to identify and infiltrate sensitive networks globally across critical infrastructure sectors. This disclosure emphasizes the role of private-sector intermediaries in scaling state-sponsored cyber operations, and organizations are advised to prioritize resilience against botnet-driven reconnaissance and credential-based exploitation.

## Impact

Integrity Tech's activities enable persistent access to sensitive data for organizations across a broad range of global sectors, including critical infrastructure. The use of large-scale botnets and AI-driven automation significantly increases the threat surface for potential targets, allowing for rapid identification and exploitation of vulnerabilities. Previous activities attributed to groups utilizing this infrastructure have resulted in long-term network compromises and the exfiltration of confidential intelligence.

## Recommendation

- Consult the joint advisory published by the FBI and international partners at https://www.ic3.gov/CSA/2026/261008.pdf for specific mitigation guidance related to botnet infrastructure.
- Enhance monitoring of egress traffic to identify potential communication with known botnet command-and-control infrastructure often utilized by groups such as Flax Typhoon.
- Conduct thorough reviews of internet-facing assets for unauthorized scanning and exploitation patterns, specifically targeting web vulnerabilities and weak authentication.
- Implement robust perimeter defense and segmentation to limit the reach of compromised accounts or botnet-controlled entry points.
