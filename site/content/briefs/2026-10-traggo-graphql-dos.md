---
brief_id: brief-2026-10-30-traggo-graphql-dos
event_id: brief-2026-10-30-traggo-graphql-dos
revision: 1
activity_at: "2026-10-30T11:42:01Z"
title: 'Traggo Server: Unauthenticated Denial of Service via GraphQL Alias Overloading (CVE-2026-117184)'
slug: 2026-10-traggo-graphql-dos
description: Traggo server v0.8.3 is vulnerable to an unauthenticated Denial of Service due to a lack of complexity and size limits on the /graphql endpoint, allowing attackers to exhaust CPU and memory resources.
date: "2026-10-30T11:42:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:traggo:server:0.8.3:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - graphql
  - webserver
vendors:
  - Traggo
products:
  - Traggo server (0.8.3)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Traggo server v0.8.3 is vulnerable to an Unauthenticated Denial of Service (DoS).
    confidence_band: high
cves:
  - id: CVE-2026-117184
    kev_status: unknown
references:
  - https://github.com/traggo/server/issues/253
  - https://sploitus.com/exploit?id=033DC789-DD73-5F12-8843-333C271C994A
  - https://sploitus.com/exploit?id=033DC789-DD73-5F12-8843-333C271C994A&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-117184 Exploitation - GraphQL Alias Overloading
    description: Detects potential GraphQL alias overloading attempts by monitoring for high-frequency field aliases in POST requests to /graphql
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1498
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify all public-facing instances of Traggo server and restrict access to the /graphql endpoint
      owner: IT Operations
      due: 24h
      evidence: Vulnerability is exploitable unauthenticated
  hunt_leads:
    - lead: Search web server logs for POST requests to /graphql containing repetitive alias patterns
      technique_id: T1498
      data_needed:
        - HTTP POST request body logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Payload consists of repetitive vN:version{name} strings
  mitigation_plan:
    - priority: immediate
      action: Implement request body size limits and GraphQL complexity limiting in handler.go
      owner: IT Operations
      addresses: CVE-2026-117184
      evidence: Root cause analysis in source
---

Traggo server version 0.8.3 is vulnerable to an unauthenticated Denial of Service (CVE-2026-117184). The application lacks input size validation on the `/graphql` endpoint and fails to enforce complexity limits for GraphQL queries. An attacker can submit a crafted request containing a large number of aliased fields, forcing the server to perform excessive resolver operations, leading to CPU exhaustion and high memory usage (OOM). The vulnerability is currently reserved and the project is awaiting a fix.

## Impact

Successful exploitation allows an unauthenticated attacker to induce high CPU usage and significant memory pressure. A single payload of approximately 2 MB with 100,000 aliases was observed to consume nearly 1 GB of RAM and pin a CPU core for over 100 seconds, potentially rendering the service unresponsive.

## Recommendation

* Implement `http.MaxBytesReader` on the `/graphql` handler to restrict request body size to a reasonable threshold (e.g., 1 MB).
* Configure the GraphQL handler to enforce a `ComplexityLimit` to prevent resource-intensive queries.
* Restrict access to the `version` field by applying an authentication directive such as `@hasRole(role: USER)` in `schema.graphql`.
* Monitor Traggo server repository for the release of version 0.8.4 or subsequent patches.
