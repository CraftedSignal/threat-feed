---
brief_id: brief-2026-11-20-nats-server-mqtt-dos-ghsa-r72h-j7qq-v6qg
event_id: brief-2026-11-20-nats-server-mqtt-dos-ghsa-r72h-j7qq-v6qg
revision: 1
activity_at: "2026-11-20T02:04:45Z"
title: 'NATS Server: Unauthenticated MQTT memory exhaustion (CVE-2026-58210)'
slug: 2026-11-nats-server-mqtt-dos-ghsa-r72h-j7qq-v6qg
description: NATS Server is vulnerable to a remote denial-of-service attack where an unauthenticated attacker can exhaust server memory by sending incomplete MQTT CONNECT packets that the server persists in memory while awaiting full packet delivery.
date: "2026-11-20T02:04:45Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:linuxfoundation:nats-server:*:*:*:*:*:*:*:*
vendors:
  - NATS
products:
  - NATS Server
product_versions:
  - product: NATS Server
    range: < 2.12.12
  - product: NATS Server
    range: '>= 2.14.0-RC.1, < 2.14.3'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated MQTT client could cause the server to retain large incomplete MQTT CONNECT packets before authentication completed, consuming server memory while the parser waited for the advertised MQTT packet length.
    confidence_band: high
cves:
  - id: CVE-2026-58210
    cvss: 7.5
    epss: 0.00742
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-r72h-j7qq-v6qg
  - https://cveawg.mitre.org/api/cve/CVE-2026-58210
action_plan:
  priority: elevated
  hunt_leads:
    - lead: Identify NATS server instances experiencing spikes in memory utilization correlated with high volumes of incomplete or long-duration unauthenticated MQTT connection attempts.
      technique_id: T1499
      data_needed:
        - NATS server process memory usage metrics
        - NATS server connection logs
        - Network connection state metrics
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: An unauthenticated MQTT client could cause the server to retain large incomplete MQTT CONNECT packets before authentication completed, consuming server memory while the parser waited for the advertised MQTT packet length.
  mitigation_plan:
    - priority: immediate
      action: Upgrade NATS Server to 2.12.12 or 2.14.3
      evidence: The issue is fixed in v2.14.3 and v2.12.12.
    - priority: short_term
      action: Disable MQTT support if not required
      evidence: Deployments not using MQTT are not affected.
  gaps:
    - No specific Sigma rule possible due to lack of log-observable patterns for individual packet parsing states in standard NATS logs.
---

## Overview
NATS Server is prone to a memory exhaustion vulnerability (CVE-2026-58210) affecting its MQTT parsing implementation. An unauthenticated attacker can initiate an MQTT connection and transmit incomplete CONNECT packets. The server retains this partial data in memory until the authentication timeout, allowing an attacker to consume system resources by repeatedly opening connections and sending these malformed packets.

## Impact
Successful exploitation leads to a denial-of-service (DoS) condition by exhausting available server memory, potentially affecting the availability of the NATS messaging infrastructure.

## Recommendation
- Prioritize patching NATS Server to version 2.12.12 or 2.14.3 depending on the version branch currently in production.
- Deployments that do not utilize the MQTT protocol should disable it to mitigate the attack vector.
- Monitor server resource utilization (memory) for spikes associated with incoming unauthenticated connection attempts.
