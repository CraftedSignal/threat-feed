---
brief_id: brief-2026-11-19-nats-mqtt-injection-ghsa-qrcv-3558-gj4f
event_id: brief-2026-11-19-nats-mqtt-injection-ghsa-qrcv-3558-gj4f
revision: 1
activity_at: "2026-11-19T16:40:00Z"
title: NATS Server MQTT protocol injection (CVE-2026-58213)
slug: 2026-11-nats-mqtt-injection-ghsa-qrcv-3558-gj4f
description: NATS Server is vulnerable to MQTT protocol injection via crafted subscription filters that allow attackers to inject arbitrary NATS commands into routed or leafnode connections.
date: "2026-11-19T16:40:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
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
tags:
  - attack.execution
  - attack.t1059
vendors:
  - NATS
products:
  - NATS Server
product_versions:
  - product: NATS Server
    range: < 2.12.9
  - product: NATS Server
    range: '>= 2.14.0-RC.1, < 2.14.1'
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An MQTT client could include protocol control characters in subscription filters that were later forwarded as NATS protocol data to route or leafnode connections, corrupting the forwarded protocol stream and allowing injection of unintended NATS protocol operations.
    confidence_band: high
cves:
  - id: CVE-2026-58213
    cvss: 7.1
    epss: 0.00441
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-qrcv-3558-gj4f
  - https://cveawg.mitre.org/api/cve/CVE-2026-58213
action_plan:
  priority: immediate_escalation
  immediate_actions:
    - action: Upgrade NATS Server to 2.12.9 or 2.14.1
      evidence: The issue is fixed in v2.14.1 and v2.12.9.
    - action: Disable anonymous MQTT access in NATS Server
      evidence: Anonymous MQTT deployments are higher risk because no credentials are required to reach the affected parser.
  hunt_leads:
    - lead: Monitor NATS server logs for MQTT subscription patterns containing unusual control characters or characters typically outside expected subscription filter syntax.
      technique_id: T1059
      data_needed:
        - NATS server logs
        - MQTT protocol metadata
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: An MQTT client could include protocol control characters in subscription filters that were later forwarded as NATS protocol data.
---

## Overview
NATS Server is susceptible to a protocol injection vulnerability (CVE-2026-58213) in its MQTT support. An MQTT client can include control characters in a subscription filter which are subsequently forwarded as NATS protocol commands when using route or leafnode connections. This allows for the injection of unauthorized NATS operations across cluster nodes or account boundaries. Deployments using anonymous MQTT access are at the highest risk, as no authentication is required to interact with the vulnerable parser.

## Impact
Successful exploitation can result in the injection of unintended NATS commands across cluster nodes, potentially leading to unauthorized operations within the messaging architecture. Confidentiality is identified as a primary impact area due to the ability to manipulate cross-account or cross-node traffic flows.

## Recommendation
- Immediate Upgrade: Update NATS Server to version 2.12.9 or 2.14.1 to remediate this vulnerability.
- Configuration Change: Disable anonymous MQTT access in NATS Server configurations where it is not required for production services.
- Inventory: Audit current NATS deployments to identify instances using MQTT subscriptions, specifically those that facilitate cross-cluster or cross-account communication via leafnode or route forwarding.
