---
brief_id: brief-2026-11-06-axis2-ssrf
event_id: brief-2026-11-06-axis2-ssrf
revision: 2
activity_at: "2026-11-08T08:32:37Z"
revision_history:
  - revision: 2
    at: "2026-11-08T08:32:37Z"
    checksum: sha256:f49f83c17a9c80b7c725c5e39d9298d30cd41fe83254e9efe55845fb12f07f7c
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=0F37FEA9-A030-5852-BE90-FDCECB73262F&utm_source=rss&utm_medium=rss
title: 'Apache Axis2/Java: SSRF via WS-Addressing endpoints (CVE-2026-123753)'
slug: 2026-11-axis2-ssrf
description: Apache Axis2/Java versions prior to 2.0.2 are vulnerable to unauthenticated SSRF, allowing attackers to force the server to initiate requests to arbitrary network destinations.
date: "2026-11-06T19:23:13Z"
lastmod: "2026-11-08T08:31:38Z"
type: advisory
claim_state: <nil>
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
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=0F37FEA9-A030-5852-BE90-FDCECB73262F&utm_source=rss&utm_medium=rss
vendors:
  - Apache
products:
  - Axis2/Java (< 2.0.2)
cves:
  - id: CVE-2026-123753
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/557
  - https://sploitus.com/exploit?id=0F37FEA9-A030-5852-BE90-FDCECB73262F&utm_source=rss&utm_medium=rss
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
updates:
  - at: "2026-11-08T08:31:38Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=0F37FEA9-A030-5852-BE90-FDCECB73262F&utm_source=rss&utm_medium=rss
---

Apache Axis2/Java versions prior to 2.0.2 are vulnerable to Server-Side Request Forgery (SSRF). An unauthenticated attacker can supply a non-anonymous WS-Addressing 'wsa:ReplyTo' or 'wsa:FaultTo' header, causing the service to initiate a connection to the specified address. This can lead to unauthorized access to internal resources or sensitive network infrastructure.

## Impact

Successful exploitation allows attackers to perform requests to internal hosts accessible by the Axis2 server, potentially bypassing network segmentation or accessing internal services that do not require authentication.

## Recommendation

* Upgrade Apache Axis2/Java to version 2.0.2 or later immediately.
* Audit web server and application logs for unusual 'wsa:ReplyTo' or 'wsa:FaultTo' address patterns in SOAP headers.
* Restrict egress traffic from the application server to prevent unauthorized internal network access.
