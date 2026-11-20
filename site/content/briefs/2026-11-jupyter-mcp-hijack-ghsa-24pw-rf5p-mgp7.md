---
brief_id: brief-2026-11-20-jupyter-mcp-hijack-ghsa-24pw-rf5p-mgp7
event_id: brief-2026-11-20-jupyter-mcp-hijack-ghsa-24pw-rf5p-mgp7
revision: 1
activity_at: "2026-11-20T02:04:04Z"
title: Datalayer Jupyter MCP Server Unauthenticated Management Route Hijacking
slug: 2026-11-jupyter-mcp-hijack-ghsa-24pw-rf5p-mgp7
description: Datalayer Jupyter MCP Server versions prior to 1.0.3 fail to enforce authentication on management routes when running in standalone streamable-http mode, allowing unauthenticated network callers to hijack the Jupyter backend and stop the notebook kernel.
date: "2026-11-20T02:04:04Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:datalayer:jupyter-mcp-server:*:*:*:*:*:*:*:*
has_poc: true
tags:
  - cve-2026-77318
vendors:
  - datalayer
products:
  - jupyter-mcp-server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated network caller can use /api/connect to replace runtime_url and document_url values and their tokens, reset ServerContext, and start a kernel client against attacker-controlled infrastructure.
cves:
  - id: CVE-2026-77318
    kev_status: "false"
references:
  - https://cveawg.mitre.org/api/cve/CVE-2026-77318
  - https://github.com/advisories/GHSA-24pw-rf5p-mgp7
rules:
  - title: Unauthorized Access to Jupyter MCP Management Routes
    description: Detects attempts to access the management routes /api/connect or /api/stop, which were unauthenticated in vulnerable versions of jupyter-mcp-server.
    platform: sigma
    severity: high
    data_sources:
      - webserver
rules_count: 1
---

## Overview
Jupyter MCP Server is a Model Context Protocol server for Jupyter. In standalone streamable-http mode, versions prior to 1.0.3 enforce `MCP_TOKEN` authentication on the `/mcp` endpoint but fail to enforce it on the state-changing `/api/connect` and `/api/stop` management routes. This boundary failure occurs outside of normal MCP JSON-RPC tool dispatch and does not require explicit insecure no-auth mode.

## Attack Chain
An unauthenticated network caller can invoke the `PUT /api/connect` route to replace `runtime_url` and `document_url` values, reset `ServerContext`, and start a kernel client against attacker-controlled infrastructure. This causes the server to send Jupyter API and WebSocket traffic to that attacker-controlled backend. Additionally, an unauthenticated caller can use the `DELETE /api/stop` route to stop the current notebook kernel.

## Impact
Successful exploitation allows an unauthenticated attacker to manipulate the active backend connection of the Jupyter MCP server, redirecting sensitive Jupyter API and WebSocket traffic to attacker-controlled infrastructure. Furthermore, the attacker can cause a denial of service by stopping the current notebook kernel.

## Recommendation
Upgrade `jupyter-mcp-server` to version 1.0.3 or later to address the authentication boundary failure on management routes.
