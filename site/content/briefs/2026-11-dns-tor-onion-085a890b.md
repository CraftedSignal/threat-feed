---
brief_id: brief-2026-11-10-dns-tor-onion-085a890b
event_id: brief-2026-11-10-dns-tor-onion-085a890b
revision: 1
activity_at: "2026-11-10T15:08:48Z"
title: DNS query for Tor onion domains
slug: 2026-11-dns-tor-onion-085a890b
description: Detection of anomalous DNS queries to .onion addresses and Tor-to-web proxy services, which may indicate unauthorized network routing or C2 activity.
date: "2026-11-10T15:08:48Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Logic validated against industry-standard Tor detection patterns
tags:
  - network-security
  - tor
  - dns-monitoring
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090.003
    technique_name: Multi-hop Proxy
    evidence: Detects DNS queries to an .onion address related to Tor routing networks
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/dns_query/dns_query_win_tor_onion_domain_query.yml
  - https://web.archive.org/web/20260310035047/https://www.logpoint.com/en/blog/detecting-tor-use-with-logpoint/
rules:
  - title: Detect DNS Query for Tor Onion Domains
    description: Detects DNS queries for .onion addresses and known Tor-to-web gateway domains that facilitate Tor network access
    platform: sigma
    severity: high
    tactics:
      - command-and-control
    techniques:
      - T1090.003
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
    - action: Deploy Sigma rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides valid detection logic for Tor-related DNS queries
  hunt_leads:
    - lead: Identify endpoints querying high volumes of Tor-related domains
      technique_id: T1090.003
      data_needed:
        - DNS logs
        - Proxy logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Repeated queries to .onion or Tor2Web domains suggest consistent use of anonymization services
---

This intelligence identifies specific DNS query patterns associated with Tor network resolution, including direct '.onion' TLD requests and the use of Tor-to-web gateway services. These domains facilitate access to anonymized services from standard internet environments. Monitoring these requests is a common mechanism for identifying the use of anonymization tools that may bypass organizational network security controls or facilitate command and control (C2) communication.

## Recommendation
- Enable Sysmon DNS Query logging (Event ID 22) to capture domain resolution attempts.
- Deploy the provided Sigma rule to detect and alert on these resolution patterns.
- Investigate the originating process and host identity for any alert triggers, as legitimate Tor browser usage or malicious proxying may occur.
- Implement a DNS filtering blocklist for known Tor2Web proxy domains if such resolution is prohibited by organizational policy.
