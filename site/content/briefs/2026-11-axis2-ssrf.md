---
brief_id: brief-2026-11-06-axis2-ssrf
event_id: brief-2026-11-06-axis2-ssrf
revision: 1
activity_at: "2026-11-06T19:23:13Z"
title: 'Apache Axis2/Java: SSRF via WS-Addressing endpoints (CVE-2026-123753)'
slug: 2026-11-axis2-ssrf
description: Apache Axis2/Java versions prior to 2.0.2 are vulnerable to unauthenticated SSRF, allowing attackers to force the server to initiate requests to arbitrary network destinations.
date: "2026-11-06T19:23:13Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
vendors:
  - Apache
products:
  - Axis2/Java (< 2.0.2)
cves:
  - id: CVE-2026-123753
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/557
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Apache Axis2/Java to version 2.0.2 or later
      owner: IT Operations
      due: 48h
      evidence: Vulnerability addressed in Apache Axis2/Java 2.0.2
  hunt_leads:
    - lead: Inspect web application logs for SOAP messages containing non-anonymous wsa:ReplyTo or wsa:FaultTo endpoints targeting internal IP ranges.
      data_needed:
        - Web server access logs
        - Application-level SOAP request logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: An unauthenticated caller could supply a non-anonymous WS-Addressing wsa:ReplyTo or wsa:FaultTo address
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Axis2/Java 2.0.2
      owner: IT Operations
      addresses: CVE-2026-123753
      evidence: Fixed in Apache Axis2/Java 2.0.2
---

Apache Axis2/Java versions prior to 2.0.2 are vulnerable to Server-Side Request Forgery (SSRF). An unauthenticated attacker can supply a non-anonymous WS-Addressing 'wsa:ReplyTo' or 'wsa:FaultTo' header, causing the service to initiate a connection to the specified address. This can lead to unauthorized access to internal resources or sensitive network infrastructure.

## Impact

Successful exploitation allows attackers to perform requests to internal hosts accessible by the Axis2 server, potentially bypassing network segmentation or accessing internal services that do not require authentication.

## Recommendation

* Upgrade Apache Axis2/Java to version 2.0.2 or later immediately.
* Audit web server and application logs for unusual 'wsa:ReplyTo' or 'wsa:FaultTo' address patterns in SOAP headers.
* Restrict egress traffic from the application server to prevent unauthorized internal network access.
