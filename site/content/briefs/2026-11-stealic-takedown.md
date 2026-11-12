---
brief_id: brief-2026-11-12-stealic-takedown
event_id: brief-2026-11-12-stealic-takedown
revision: 1
activity_at: "2026-11-12T16:43:53Z"
title: International law enforcement disrupts StealC, Gootloader, and CastleRAT malware infrastructure
slug: 2026-11-stealic-takedown
description: International law enforcement disrupted 235 servers and 257 domains used by StealC, Gootloader, and CastleRAT malware, identifying approximately 6.4 million stolen credentials.
date: "2026-11-12T16:43:53Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://therecord.media/european-authorities-take-down-stealic-malware-second-time
  observed_at: "2026-11-12T00:00:00Z"
  confidence: high
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
tags:
  - malware
  - infostealer
  - c2
  - takedown
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: European police dismantled more than 100 servers used by the StealC password-stealing malware this week.
    confidence_band: high
references:
  - https://therecord.media/european-authorities-take-down-stealic-malware-second-time
action_plan:
  hunt_leads:
    - lead: Identify outbound network connections to infrastructure associated with StealC, Gootloader, or CastleRAT, specifically focusing on traffic patterns to domains and servers identified as part of the rebuilt infrastructure after law enforcement takedowns.
      technique_id: T1071
      data_needed:
        - Network flow logs
        - DNS query logs
        - Proxy logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: European police dismantled more than 100 servers used by the StealC password-stealing malware this week, marking the second such takedown; Europol said a wider international operation this week saw law enforcement agencies and private sector partners disrupt 235 servers and 257 domains used by StealC alongside the Gootloader and CastleRAT malware.
---

European and international authorities, including police from Germany, the Netherlands, Britain, and the United States, conducted an operation to dismantle infrastructure linked to the StealC, Gootloader, and CastleRAT malware. Investigators traced the network to the Virtualine bulletproof hosting provider. This action follows a previous takedown of related infrastructure in June.

## Impact
Law enforcement disrupted 235 servers and 257 domains. Investigators uncovered approximately 6.4 million stolen login credentials from more than 40,000 victims.

## Recommendation
Individuals are encouraged to visit police-sanctioned resources such as politie.nl/checkyourhack or haveibeenpwned.com to check for potential compromise and review recommended remediation steps.
