---
brief_id: brief-2026-11-10-cobalt-strike-dns-9238ef5a
event_id: brief-2026-11-10-cobalt-strike-dns-9238ef5a
revision: 1
activity_at: "2026-11-10T03:35:45Z"
title: 'Cobalt Strike: Suspicious DNS beaconing patterns'
slug: 2026-11-cobalt-strike-dns-9238ef5a
description: This detection addresses suspicious DNS query patterns associated with Cobalt Strike beaconing activity as documented by the SigmaHQ project.
date: "2026-11-10T03:35:45Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Detection logic based on established open-source intelligence.
tags:
  - cobalt-strike
  - c2
  - dns-tunneling
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    subtechnique_id: T1071.004
    subtechnique_name: DNS
    evidence: Detects a program that invoked suspicious DNS queries known from Cobalt Strike beacons
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_client/win_dns_client_mal_cobaltstrike.yml
  - https://www.icebrg.io/blog/footprints-of-fin7-tracking-actor-patterns
  - https://web.archive.org/web/20211022162145/https://www.sekoia.io/en/hunting-and-detecting-cobalt-strike/
rules:
  - title: Detect Suspicious Cobalt Strike DNS Beaconing
    description: Detects DNS queries known to be used by Cobalt Strike beacons based on naming patterns in the query string.
    platform: sigma
    severity: critical
    tactics:
      - command_and_control
    techniques:
      - T1071.004
    data_sources:
      - dns_query
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable Microsoft-Windows-DNS Client/Operational logging across the fleet
      owner: IT Operations
      due: 48h
      evidence: Required to generate Event ID 3008
    - action: Deploy Sigma rule for Cobalt Strike DNS detection
      owner: Detection Engineering
      due: 24h
      evidence: SigmaHQ/sigma-hq rule mapping
  hunt_leads:
    - lead: Search existing DNS logs for historical occurrences of .stage. or post.1 query prefixes
      technique_id: T1071.004
      data_needed:
        - DNS query logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Known patterns associated with Cobalt Strike DNS C2
---

This brief provides detection logic for identifying specific DNS query structures historically associated with Cobalt Strike beaconing. These query patterns are often observed during command and control (C2) communication when the beacon is configured to use DNS as a transport mechanism.

## Recommendation
- Enable the Microsoft-Windows-DNS Client/Operational event log to capture the telemetry required for this rule.
- Deploy the provided Sigma rule to your SIEM to monitor for DNS queries matching known Cobalt Strike patterns.
- Investigate any DNS queries identified by this rule for potential C2 activity, particularly those originating from unauthorized or sensitive internal hosts.
