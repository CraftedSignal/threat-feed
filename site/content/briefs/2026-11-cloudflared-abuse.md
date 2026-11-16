---
brief_id: brief-2026-11-16-cloudflared-abuse
event_id: brief-2026-11-16-cloudflared-abuse
revision: 1
activity_at: "2026-11-16T17:30:07Z"
title: Abuse of Cloudflared for Network Tunneling
slug: 2026-11-cloudflared-abuse
description: Threat actors are increasingly abusing the legitimate Cloudflared utility to establish persistent network tunnels, facilitating communication that mimics ingress-as-a-service behavior.
date: "2026-11-16T17:30:07Z"
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
tags:
  - c2
  - tunneling
  - proxy
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: This hunting analytic detects network connection events possibly associated with the Cloudflared tool, a tool used to create tunnels via Cloudflare.
references:
  - https://www.bleepingcomputer.com/news/security/hackers-increasingly-abuse-cloudflare-tunnels-for-stealthy-connections/amp/
  - https://github.com/cloudflare/cloudflared
  - https://www.guidepointsecurity.com/blog/tunnel-vision-cloudflared-abused-in-the-wild/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_potential_cloudflared_network_connection.yml
rules:
  - title: Windows Potential Cloudflared Network Connection
    description: This hunting analytic detects network connection events destined for port 7844, which may be associated with the usage of the Cloudflared tool.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1572
    data_sources:
      - network_connection
      - windows
rules_count: 1
---

## Overview
Cloudflared is a utility used to create tunnels via Cloudflare. It is functionally similar to ngrok and allows for the creation of tunnels that reach out to Cloudflare Edge Servers via HTTPS, HTTP2, or QUIC. Threat actors are known to abuse this legitimate tool to create tunnels, allowing for access to private networks or services. 

## Attack Chain
- **Command and Control (T1572):** Attackers leverage Cloudflared to establish persistent outbound network tunnels, bypassing traditional perimeter controls by initiating connections from internal hosts to Cloudflare infrastructure.

## Impact
Successful abuse of Cloudflared enables attackers to establish unauthorized tunnels, potentially exposing internal services or private networks to external access.

## Recommendation
- Review network traffic to determine if connections to Cloudflare infrastructure are authorized.
- Monitor network connections for activity over port 7844.
- Filter alerts for approved Cloudflared deployments to reduce false positives.
