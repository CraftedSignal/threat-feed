---
brief_id: brief-2026-11-05-bashlite-indicators
event_id: brief-2026-11-05-bashlite-indicators
revision: 1
activity_at: "2026-11-05T13:28:55Z"
title: 'Bashlite Botnet: New IoT Payload Delivery Infrastructure'
slug: 2026-11-bashlite-indicators
description: ThreatFox has identified 14 new URLs hosted on a single IP address used for the delivery of Bashlite (Gafgyt) malware across various IoT CPU architectures.
date: "2026-11-05T13:28:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "1"
  rating: B1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - botnet
  - iot
  - malware
  - bashlite
  - gafgyt
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1583
    technique_name: Acquire Infrastructure
    evidence: The indicators point to a centralized IP address for malicious binary hosting.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: The source documents 14 new URLs for the delivery of Bashlite malware payloads.
    confidence_band: high
references:
  - https://threatfox.abuse.ch/browse/malware/elf.bashlite/
  - https://malpedia.caad.fkie.fraunhofer.de/details/elf.bashlite
iocs:
  - type: ip
    value: 181.214.147.11
  - type: url
    value: http://181.214.147.11/armv4l
  - type: url
    value: http://181.214.147.11/arc
  - type: url
    value: http://181.214.147.11/aarch64
  - type: url
    value: http://181.214.147.11/armv6l
  - type: url
    value: http://181.214.147.11/armv5l
  - type: url
    value: http://181.214.147.11/i486
  - type: url
    value: http://181.214.147.11/armv7l
  - type: url
    value: http://181.214.147.11/mips
  - type: url
    value: http://181.214.147.11/m68k
  - type: url
    value: http://181.214.147.11/powerpc
  - type: url
    value: http://181.214.147.11/mipsel
  - type: url
    value: http://181.214.147.11/x86_64
  - type: url
    value: http://181.214.147.11/sparc
  - type: url
    value: http://181.214.147.11/sh4
ioc_counts:
  ip: 1
  url: 14
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block IP address 181.214.147.11 at edge firewalls and proxy devices.
      owner: SOC
      due: 2h
      evidence: ThreatFox identified this IP as hosting 14 malicious payload URLs.
  hunt_leads:
    - lead: Search proxy/firewall logs for any successful outbound requests to 181.214.147.11.
      technique_id: T1105
      data_needed:
        - Proxy access logs
        - Firewall traffic logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The source identified these URLs as payload delivery endpoints for Bashlite malware.
---

Abuse.ch has identified 14 new malicious URLs linked to the Bashlite (also known as Gafgyt) IoT botnet. These indicators, observed on 2026-11-04, point to binary payloads tailored for multiple CPU architectures, including ARM, MIPS, PowerPC, SPARC, and x86_64. The infrastructure is centralized on the IP address 181.214.147.11.

## Impact

The identified indicators represent active payload delivery vectors. Bashlite typically targets internet-exposed IoT devices to incorporate them into botnets for distributed denial-of-service (DDoS) operations.

## Recommendation

- Block all ingress and egress traffic to/from the IP address 181.214.147.11 at the perimeter firewall and web proxy.
- Audit network logs for any successful HTTP GET requests to the identified URLs, as these indicate potential device infection.
- Implement outbound traffic filtering to prevent IoT devices from downloading arbitrary binaries from unknown external web servers.
