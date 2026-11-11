---
brief_id: brief-2026-11-11-tsparticles-mcp-dos
event_id: brief-2026-11-11-tsparticles-mcp-dos
revision: 1
activity_at: "2026-11-11T07:31:24Z"
title: 'tsparticles: Remote Denial of Service via Unbounded HTTP Request Body Buffering'
slug: 2026-11-tsparticles-mcp-dos
description: The @tsparticles/mcp-server HTTP handler fails to restrict the size of incoming request bodies, allowing an unauthenticated attacker to cause OOM-driven process termination via a large POST request.
date: "2026-11-11T07:31:24Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - denial-of-service
  - webserver
  - oom
  - nodejs
vendors:
  - tsparticles
products:
  - '@tsparticles/mcp-server'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated remote attacker can stream an arbitrarily large body to POST /mcp, exhausting the Node.js process memory and causing a Denial of Service.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-447x-qqwf-m7xq
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit container deployments for the use of the default @tsparticles/mcp-server image.
      owner: IT Operations
      due: 24h
      evidence: Official Docker image ships with HTTP mode enabled by default on 0.0.0.0:3000.
  hunt_leads:
    - lead: Search for HTTP POST requests to /mcp with unusually high payload sizes or extended duration connections.
      technique_id: T1499
      data_needed:
        - Web server access logs
        - Application telemetry
        - Network flow logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attacker streams arbitrary large bodies to POST /mcp to exhaust memory.
  mitigation_plan:
    - priority: immediate
      action: Implement a request body size limit in the application code or a reverse proxy.
      owner: IT Operations
      addresses: Unbounded HTTP Request Body Buffering
      evidence: Suggested patch tracks cumulative bytes and destroys request when exceeding 1MB.
---

The HTTP server mode of `@tsparticles/mcp-server` is vulnerable to a Denial of Service (DoS) attack. The application's `/mcp` POST endpoint accumulates all incoming request body chunks into an in-memory `Buffer[]` array without enforcing size limits or checking the `Content-Length` header. An attacker can stream an arbitrarily large body, exhausting the Node.js process memory and triggering an OOM-killer termination. The default configuration exposes this endpoint on all network interfaces (0.0.0.0:3000) when deployed via the official Docker image.

## Impact
Successful exploitation leads to complete service unavailability of the `mcp-server` instance. The vulnerability allows an unauthenticated remote attacker to force an OOM-kill of the containerized process. No credentials are required, and the impact is limited to resource exhaustion rather than direct unauthorized data access or code execution.

## Recommendation
- Update or patch the `integrations/mcp-server/src/index.ts` file to implement a maximum body size limit during the request stream processing.
- Implement a check for the `Content-Length` header before consuming the request body.
- If immediate patching is not possible, place a reverse proxy or Web Application Firewall (WAF) in front of the service to enforce request body size limits and restrict access to the `/mcp` endpoint.
- Monitor container memory usage metrics for abnormal spikes associated with requests to the `/mcp` endpoint.
