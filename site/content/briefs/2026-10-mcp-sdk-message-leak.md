---
brief_id: brief-2026-10-20-mcp-sdk-message-leak
event_id: brief-2026-10-20-mcp-sdk-message-leak
revision: 1
activity_at: "2026-10-20T23:55:37Z"
title: 'Model Context Protocol TypeScript SDK: Cross-client message leakage (CVE-2026-111770)'
slug: 2026-10-mcp-sdk-message-leak
description: A high-severity vulnerability in the MCP TypeScript SDK (CVE-2026-111770) allows an MCP server to misroute messages between clients due to JSON-RPC request ID collisions when server instances are incorrectly shared.
date: "2026-10-20T23:55:37Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source confirmed, no further environment validation needed.
tags:
  - information-disclosure
  - mcp
  - sdk-vulnerability
vendors:
  - Model Context Protocol
products:
  - '@modelcontextprotocol/server (>= 2.0.0, < 2.3.0)'
cves:
  - id: CVE-2026-111770
    kev_status: unknown
references:
  - https://github.com/advisories/GHSA-jm63-cq47-j5jp
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade @modelcontextprotocol/server to version 2.3.0 or later.
      owner: IT Operations
      due: 48h
      evidence: Source fix recommendation
  mitigation_plan:
    - priority: immediate
      action: Refactor MCP server code to remove singleton patterns and use per-session instance creation.
      owner: Application Security
      addresses: CVE-2026-111770
      evidence: Source provided architectural guidance
---

The MCP TypeScript SDK is vulnerable to cross-client message leakage when implemented as a shared, stateless instance. Because the protocol identifies messages by JSON-RPC IDs, which typically reset at 0 for every client, concurrent requests reaching a shared `McpServer` or transport instance result in ID collisions. In this state, an MCP server may erroneously return one client's responses or push notifications to another client sharing the same instance. This behavior was unintentionally encouraged by early SDK documentation, which provided examples using globally initialized server instances in common Node.js frameworks like Hono, Express, and Fastify. The vulnerability affects `@modelcontextprotocol/server` versions 2.0.0 through 2.2.0. Successful exploitation allows for sensitive information disclosure between authorized clients interacting with the same MCP server instance.

## Impact

Successful exploitation results in unauthorized data access where clients receive responses or notifications intended for other users. This impacts any multi-user environment where a single MCP server is exposed via HTTP and initialized as a singleton. Organizations relying on this SDK for integrating LLM tools or internal automation are at risk of cross-session data leakage.

## Recommendation

1. Upgrade the `@modelcontextprotocol/server` package to version 2.3.0 or later to ensure the SDK actively enforces connection isolation and rejects attempts to share instances.
2. Audit all existing MCP server implementations for the singleton pattern; refactor code to instantiate `McpServer` and transport objects either per-request or per-session using a `sessionIdGenerator`.
3. Validate implementation patterns against the official SDK update guidance to ensure session-specific state management is strictly applied.
