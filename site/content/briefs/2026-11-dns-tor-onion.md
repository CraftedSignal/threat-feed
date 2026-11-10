---
brief_id: brief-2026-11-10-dns-tor-onion
event_id: brief-2026-11-10-dns-tor-onion
revision: 1
activity_at: "2026-11-10T02:41:44Z"
title: Detection of Tor Onion Service DNS Resolution
slug: 2026-11-dns-tor-onion
description: This detection identifies Windows DNS Client events associated with Tor routing or Tor2Web proxy services, which are often used for anonymous command and control (C2) communication.
date: "2026-11-10T02:41:44Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs local environment validation
tags:
  - tor
  - c2
  - dns
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    subtechnique_id: T1090.003
    subtechnique_name: Multi-hop Proxy
    evidence: Detects DNS resolution of an .onion address related to Tor routing networks
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/dns_client/win_dns_client_tor_onion.yml
  - https://web.archive.org/web/20260310035047/https://www.logpoint.com/en/blog/detecting-tor-use-with-logpoint/
rules:
  - title: Detect DNS Resolution of Tor Onion and Proxy Domains
    description: Detects DNS resolution of .onion addresses and known Tor2Web proxy suffixes potentially indicating C2 communication or anonymous browsing.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1090.003
    data_sources:
      - dns_query
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable Microsoft-Windows-DNS Client operational logging
      owner: IT Operations
      due: 48h
      evidence: Source requires DNS Client operational logs for rule functionality
  hunt_leads:
    - lead: Querying of non-standard TLDs indicative of Tor proxies
      technique_id: T1090.003
      data_needed:
        - DNS query logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Source lists explicit Tor2Web proxy domains used in malicious activity
  mitigation_plan:
    - priority: medium
      action: Implement DNS filtering to block known malicious Tor2Web proxies
      owner: Network Security
      addresses: Tor proxy domains
      evidence: Domains listed in the detection logic
---

This brief documents a detection capability for identifying systems attempting to resolve Tor-related domains via standard Windows DNS resolution. Malicious actors frequently leverage Tor hidden services or Tor2Web proxies to anonymize C2 traffic and bypass traditional network perimeter defenses. The detection relies on Windows DNS Client operational logs to identify queries for domains that map to the Tor network.

## Recommendation

* Enable the "Microsoft-Windows-DNS Client Events/Operational" log channel on all Windows endpoints to ensure these events are captured.
* Deploy the provided Sigma rule to your SIEM to monitor for DNS queries targeting Tor-related suffixes.
* Investigate any host triggering this rule to determine if the activity is originating from authorized Tor browser usage or potentially malicious C2 beaconing.
