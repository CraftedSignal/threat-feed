---
brief_id: brief-2026-11-20-obsidian-sync-mcp-rce-ghsa-mx6p-3fg7-v6pj
event_id: brief-2026-11-20-obsidian-sync-mcp-rce-ghsa-mx6p-3fg7-v6pj
revision: 1
activity_at: "2026-11-20T02:07:43Z"
title: 'obsidian-sync-mcp: Host and Origin header validation bypass (CVE-2026-77283)'
slug: 2026-11-obsidian-sync-mcp-rce-ghsa-mx6p-3fg7-v6pj
description: The obsidian-sync-mcp server improperly validates Host and Origin headers when running in no-auth mode, allowing remote attackers to invoke the MCP tool surface via DNS rebinding or cross-origin requests.
date: "2026-11-20T02:07:43Z"
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
cpes:
  - cpe:2.3:a:es617:obsidian-sync-mcp:*:*:*:*:*:*:*:*
has_poc: true
tags:
  - attack.initial-access
  - attack.execution
vendors:
  - es617
products:
  - obsidian-sync-mcp
cves:
  - id: CVE-2026-77283
    epss: 0.00375
    kev_status: "false"
references:
  - https://cveawg.mitre.org/api/cve/CVE-2026-77283
  - https://github.com/advisories/GHSA-mx6p-3fg7-v6pj
---

## Overview
obsidian-sync-mcp is an MCP server that provides AI agents with access to Obsidian vaults. In versions <= 0.5.6, deployments running in no-auth mode (without an MCP_AUTH_TOKEN) fail to validate Host or Origin headers on the HTTP /mcp endpoint. This allows a malicious website visited by an operator to bypass local network security assumptions and interact with the MCP tool surface.

## Attack Chain
1. The operator runs the server in no-auth mode.
2. The operator visits an attacker-controlled website.
3. The website utilizes DNS rebinding to resolve an attacker-controlled hostname to local addresses, or performs a direct cross-origin request to the loopback address.
4. The server accepts these requests as trusted local calls, allowing the execution of MCP tool methods including reading, creating, overwriting, deleting, or moving notes.

## Impact
Unauthenticated attackers can invoke the full MCP tool surface, leading to unauthorized access to, or modification of, vault notes. In CouchDB or self-hosted LiveSync modes, vault content is equally reachable. Deployments that set MCP_AUTH_TOKEN are not affected because browsers do not attach the bearer token, resulting in an HTTP 401 response.

## Recommendation
- Upgrade to version 0.5.7, which adds application-layer Host and Origin header validation to reject unauthorized requests before any MCP method runs.
- If an upgrade is not immediate, set the MCP_AUTH_TOKEN environment variable to require authentication, which closes the path immediately.
