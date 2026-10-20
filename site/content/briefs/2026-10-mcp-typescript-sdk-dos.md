---
brief_id: brief-2026-10-20-mcp-typescript-sdk-dos
event_id: brief-2026-10-20-mcp-typescript-sdk-dos
revision: 1
activity_at: "2026-10-20T23:55:43Z"
title: 'Model Context Protocol TypeScript SDK: Memory exhaustion via array and object validation (CVE-2026-111768)'
slug: 2026-10-mcp-typescript-sdk-dos
description: The Model Context Protocol (MCP) TypeScript SDK is vulnerable to a denial-of-service condition where unauthenticated HTTP requests can exhaust server memory by bypassing array element and object key validation limits.
date: "2026-10-20T23:55:43Z"
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
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against provided source material
vendors:
  - Model Context Protocol
products:
  - '@modelcontextprotocol/sdk (1.3.0-1.31.0)'
  - '@modelcontextprotocol/server (2.0.0-2.2.0)'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: One HTTP request within the default 4 MiB size limit could exhaust the server memory, and the process aborted with JavaScript heap out of memory.
    confidence_band: high
cves:
  - id: CVE-2026-111768
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-46jr-4wx8-v453
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111768
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade all instances of @modelcontextprotocol/sdk to 1.32.0 or later
      owner: IT Operations
      due: 48h
      evidence: Fix provided by the GHSA-46jr-4wx8-v453 advisory
    - action: Upgrade all instances of @modelcontextprotocol/server to 2.3.0 or later
      owner: IT Operations
      due: 48h
      evidence: Fix provided by the GHSA-46jr-4wx8-v453 advisory
  mitigation_plan:
    - priority: immediate
      action: Configure maxToolInputElements during McpServer initialization and set maxRequestBodySize
      owner: IT Operations
      addresses: CVE-2026-111768
      evidence: Recommended mitigations in GHSA-46jr-4wx8-v453
---

The Model Context Protocol (MCP) TypeScript SDK, specifically the `@modelcontextprotocol/sdk` (versions 1.3.0 to 1.31.0) and `@modelcontextprotocol/server` (versions 2.0.0 to 2.2.0) packages, contains a memory exhaustion vulnerability (CVE-2026-111768). The SDK fails to impose validation limits on the number of array elements and object keys processed during an incoming HTTP request. An attacker can craft an HTTP request that stays within the default 4 MiB size limit but contains a highly complex or deeply nested structure, forcing the server to consume excessive memory during parsing. This results in a JavaScript heap out of memory error, causing the MCP server process to crash. This vulnerability is primarily exploitable in environments where the MCP server is exposed via HTTP to untrusted clients, such as tools configured using `McpServer`.

## Impact

Successful exploitation results in a denial-of-service (DoS) condition, rendering the affected MCP server process unavailable. This impacts applications and services relying on MCP servers for tool execution and data exchange. Infrastructure utilizing internet-facing MCP servers is at the highest risk, as the vulnerability does not require authentication unless implemented manually before the request reaches the SDK.

## Recommendation

1. Upgrade to the patched versions immediately: `@modelcontextprotocol/sdk` to 1.32.0 or later, and `@modelcontextprotocol/server` to 2.3.0 or later.
2. Implement the `maxToolInputElements` option when initializing `McpServer` to limit the number of elements and keys in tool arguments.
3. Restrict request sizes by configuring `maxRequestBodySize` on the transport or `createMcpHandler()`, or by setting limits on front-end reverse proxies or body parsers (e.g., Express or Fastify) if the SDK upgrade is not immediately possible.
4. Audit network exposures for all MCP-based services to ensure they are not unnecessarily exposed to untrusted internet traffic.
