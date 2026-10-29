---
brief_id: brief-2026-10-29-mcp-typescript-sdk-dos-eb09b16e
event_id: brief-2026-10-29-mcp-typescript-sdk-dos-eb09b16e
revision: 1
activity_at: "2026-10-29T21:02:18Z"
title: 'Model Context Protocol TypeScript SDK: Denial-of-service via unbounded JSON-RPC payloads'
slug: 2026-10-mcp-typescript-sdk-dos-eb09b16e
description: The Model Context Protocol (MCP) TypeScript SDK is vulnerable to remote denial-of-service due to a lack of request body size and JSON-RPC batch length limits, allowing unauthenticated attackers to exhaust server resources.
date: "2026-10-29T21:02:18Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source-documented patch versions and mitigation steps verified.
tags:
  - denial-of-service
  - mcp
  - nodejs
  - typescript
vendors:
  - Model Context Protocol
products:
  - '@modelcontextprotocol/sdk (1.10.0-1.30.0)'
  - '@modelcontextprotocol/server (2.0.0)'
  - '@modelcontextprotocol/node (2.0.0)'
  - '@modelcontextprotocol/hono (2.0.0)'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    subtechnique_id: T1499.004
    subtechnique_name: Application or System Exploitation
    evidence: Large requests could exhaust the server memory, and one long batch could block it from serving anyone else.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-f897-62hf-6gxq
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade vulnerable MCP packages to the specified patched versions
      owner: IT Operations
      due: 48h
      evidence: 'Upgrade to 1.x: @modelcontextprotocol/sdk 1.30.1 or later; 2.x: @modelcontextprotocol/server 2.1.0, @modelcontextprotocol/node 2.1.0 and @modelcontextprotocol/hono 2.0.1 or later.'
  hunt_leads:
    - lead: Identify MCP endpoints receiving excessively large HTTP POST requests or high-frequency JSON-RPC batch requests
      technique_id: T1499.004
      data_needed:
        - Web server access logs
        - HTTP request body size metadata
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Bodies over 4 MiB now get 413, and batches over 100 messages get 400.
  mitigation_plan:
    - priority: immediate
      action: Configure reverse proxy to enforce maximum request body size limits
      owner: IT Operations
      addresses: Denial of service via unbounded payloads
      evidence: If you cannot upgrade yet, cap request body size in a reverse proxy.
---

The Model Context Protocol (MCP) TypeScript SDK fails to enforce limits on HTTP request body sizes and the number of messages within a JSON-RPC batch. This vulnerability allows an unauthenticated attacker to send excessively large payloads or large batches to an MCP server, leading to memory exhaustion or service unavailability. Deployment configurations utilizing stdio are not affected by this vulnerability.

## Impact
Successful exploitation results in a denial-of-service condition, potentially crashing the server or preventing legitimate requests from being processed due to resource exhaustion.

## Recommendation
- Update affected packages immediately to the patched versions:
 - For 1.x environments: Update `@modelcontextprotocol/sdk` to 1.30.1 or later.
 - For 2.x environments: Update `@modelcontextprotocol/server` to 2.1.0, `@modelcontextprotocol/node` to 2.1.0, and `@modelcontextprotocol/hono` to 2.0.1 or later.
- If immediate patching is not possible, implement a request body size limit at the reverse proxy or API gateway level to mitigate payload-based exhaustion.
- Review MCP server configurations to verify if client trust boundaries allow unauthenticated access to HTTP transport endpoints.
