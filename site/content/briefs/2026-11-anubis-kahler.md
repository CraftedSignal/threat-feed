---
brief_id: brief-2026-11-07-anubis-kahler
event_id: brief-2026-11-07-anubis-kahler
revision: 1
activity_at: "2026-11-07T09:57:26Z"
title: 'Anubis Ransomware: Victim disclosure of Kahler Automation'
slug: 2026-11-anubis-kahler
description: The Anubis ransomware-as-a-service group has added Kahler Automation to its data leak site, claiming the theft of manufacturing-related data.
date: "2026-11-07T09:57:26Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Anubis
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - ransomware
  - extortion
  - data-theft
  - manufacturing
vendors:
  - Kahler Automation
products:
  - General internal corporate infrastructure
references:
  - https://www.ransomware.live/group/anubis
iocs:
  - type: ip
    value: 195.133.67.35
  - type: ip
    value: 212.224.107.203
  - type: ip
    value: 38.134.148.20
  - type: ip
    value: 5.252.177.249
ioc_counts:
  ip: 4
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block known Anubis C2 IP addresses at the perimeter firewall
      owner: SOC
      due: 2h
      evidence: Observed Anubis ransomware infrastructure IPs
  hunt_leads:
    - lead: Identify large volume outbound file transfers (exfiltration) from critical file servers
      technique_id: T1048
      data_needed:
        - NetFlow / Firewall session logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Anubis group specializes in double-extortion, necessitating data exfiltration
---

The Anubis ransomware-as-a-service (RaaS) group has claimed Kahler Automation, a German manufacturing firm, as a victim. The group alleges the exfiltration of data related to fertilizer and grain operations, publishing links to stolen data on their extortion portal. Anubis has maintained consistent activity since December 2024, focusing on the manufacturing, healthcare, and professional services sectors. The group utilizes a RaaS model and includes an optional destructive 'wipe mode' in their toolkit alongside standard encryption capabilities.

## Impact

The breach involves the suspected exfiltration of proprietary business data from Kahler Automation. No specific details regarding the operational status or extent of encryption have been confirmed by the organization.

## Recommendation

- Monitor egress traffic for connections to the listed IP addresses associated with Anubis infrastructure.
- Review internal logs for evidence of unauthorized data staging or large-volume data transfers consistent with double-extortion ransomware operations.
- Prioritize the implementation of offline, immutable backups for critical manufacturing and operational technology (OT) systems.
