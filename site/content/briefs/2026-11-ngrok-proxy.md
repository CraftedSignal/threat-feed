---
brief_id: brief-2026-11-16-ngrok-proxy
event_id: brief-2026-11-16-ngrok-proxy
revision: 1
activity_at: "2026-11-16T17:30:28Z"
title: Ngrok Reverse Proxy Usage on Network
slug: 2026-11-ngrok-proxy
description: Threat actors use the ngrok reverse proxy service to expose internal services, maintain persistence, move laterally, and proxy command-and-control traffic, which is detectable via DNS query monitoring.
date: "2026-11-16T17:30:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
products:
  - Splunk Cloud
  - Splunk Enterprise
  - Splunk Enterprise Security
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: Threat actors have used ngrok to expose internal services, including RDP and SMB, maintain persistence, move laterally, and proxy command-and-control traffic.
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: Threat actors have used ngrok to expose internal services, including RDP and SMB, maintain persistence, move laterally, and proxy command-and-control traffic.
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1102
    technique_name: Web Service
    evidence: Threat actors have used ngrok to expose internal services, including RDP and SMB, maintain persistence, move laterally, and proxy command-and-control traffic.
references:
  - https://github.com/splunk/security_content/blob/main/detections/network/ngrok_reverse_proxy_on_network.yml
  - https://ngrok.com/docs/gateway/domains
  - https://ngrok.com/docs/gateway/domains/custom-domains
  - https://ngrok.com/docs/gateway/agent/cli
  - https://attack.mitre.org/software/S0508/
  - https://www.cisa.gov/uscert/sites/default/files/publications/aa22-320a_joint_csa_iranian_government-sponsored_apt_actors_compromise_federal%20network_deploy_crypto%20miner_credential_harvester.pdf
  - https://www.cisa.gov/sites/default/files/2024-08/aa24-241a-iran-based-cyber-actors-enabling-ransomware-attacks-on-us-organizations_0.pdf
  - https://www.trendmicro.com/en_us/research/24/j/earth-simnavaz-cyberattacks.html
  - https://www.microsoft.com/en-us/security/blog/2023/06/14/cadet-blizzard-emerges-as-a-novel-and-distinct-russian-threat-actor/
  - https://thedfirreport.com/2024/08/12/threat-actors-toolkit-leveraging-sliver-poshc2-batch-scripts/
  - https://github.com/benyG/Invoke-Ngrok
  - https://www.sophos.com/en-us/blog/rapid-response-the-ngrok-incident-guide
iocs:
  - type: domain
    value: korgn.su.lennut.com
ioc_counts:
  domain: 1
rules:
  - title: Ngrok Reverse Proxy on Network
    description: This analytic detects DNS lookups to ngrok-managed endpoint domains, agent gateway domains, CNAME targets, and a CISA-reported ngrok-themed domain.
    platform: sigma
    severity: medium
    techniques:
      - T1090
      - T1102
      - T1572
    data_sources:
      - dns_query
rules_count: 1
---

## Overview
Threat actors have used ngrok to expose internal services, including RDP and SMB, maintain persistence, move laterally, and proxy command-and-control traffic. Because ngrok is also a legitimate developer and remote-access service, monitoring should account for approved usage baselines. Detection focuses on identifying DNS lookups related to ngrok-managed domains, agent gateways, and known indicators.

## Attack Chain
Threat actors use ngrok to establish network tunnels. This is identified by monitoring DNS queries for specific ngrok-managed domains, TCP tunnel hostnames, agent gateway lookups, and generated endpoint labels.

## Impact
Misuse of ngrok enables unauthorized external access to internal services, facilitating persistence, lateral movement, and command-and-control communication.

## Recommendation
- Implement monitoring for DNS queries to ngrok-managed domains.
- Establish a baseline of authorized ngrok usage to differentiate legitimate developer activity from unauthorized tunnel creation.
- Prioritize investigations into TCP tunnel endpoints, generated-looking endpoint labels, and identified CISA-reported domains (e.g., 'korgn.su.lennut.com').
