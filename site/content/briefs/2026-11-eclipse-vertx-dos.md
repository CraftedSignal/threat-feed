---
brief_id: brief-2026-11-03-eclipse-vertx-dos
event_id: brief-2026-11-03-eclipse-vertx-dos
revision: 1
activity_at: "2026-11-03T18:02:21Z"
title: 'Eclipse Vert.x: Denial of Service via vertx-stomp FrameParser (CVE-2026-118487)'
slug: 2026-11-eclipse-vertx-dos
description: The FrameParser component in vertx-stomp fails to limit record sizes, allowing an attacker to cause JVM heap exhaustion and process crashes via continuous byte streams.
date: "2026-11-03T18:02:21Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified; standard patch management workflow applicable.
cpes:
  - cpe:2.3:a:eclipse:vertx:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - memory-exhaustion
  - java
  - vulnerability
vendors:
  - Eclipse Foundation
products:
  - Eclipse Vert.x (4.0.0-4.5.35, 5.0.0-5.2.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Sustained byte streaming exhausts JVM heap memory, crashing the affected process and causing a complete denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-118487
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118487
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory applications using the vertx-stomp library to assess exposure.
      owner: IT Operations
      due: 48h
      evidence: The FrameParser component in vertx-stomp fails to impose a limit on record sizes via maxRecordSize when parsing STOMP frames.
  hunt_leads:
    - lead: Monitor JVM heap memory metrics for sustained, abnormal increases coinciding with STOMP traffic volume.
      technique_id: T1499
      data_needed:
        - JVM heap usage metrics (e.g., JMX, monitoring agents)
        - STOMP connection logs
      priority: medium
      confidence: medium
      disposition: monitor_or_close
      evidence: Sustained byte streaming exhausts JVM heap memory, crashing the affected process and causing a complete denial of service.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Eclipse Vert.x to a version beyond 4.5.35 or 5.2.2 that contains the fix for CVE-2026-118487.
      owner: IT Operations
      addresses: CVE-2026-118487
      evidence: In Eclipse Vert.x versions [4.0.0, 4.5.35] or [5.0.0, 5.2.2], the FrameParser in vertx-stomp creates a RecordParser without setting maxRecordSize.
---

Eclipse Vert.x versions [4.0.0, 4.5.35] and [5.0.0, 5.2.2] contain a vulnerability in the `FrameParser` component of `vertx-stomp`. The parser creates a `RecordParser` without enforcing a `maxRecordSize`. Consequently, if a peer streams data continuously without a newline character, the parser accumulates this data in memory indefinitely. Both STOMP clients and servers are susceptible to this memory exhaustion attack, which results in a complete denial of service for the affected process.

## Impact
Successful exploitation results in JVM heap memory exhaustion, leading to the crash of the affected STOMP client or server process.

## Recommendation
- Identify all applications utilizing `vertx-stomp` within the organization.
- Upgrade affected Eclipse Vert.x deployments to versions addressing this vulnerability (check vendor advisories for specific patched releases beyond 4.5.35 and 5.2.2).
- Implement monitoring for JVM memory usage patterns to detect anomalous heap growth associated with STOMP connections.
