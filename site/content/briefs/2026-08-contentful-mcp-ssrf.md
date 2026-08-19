---
title: Contentful MCP Tools SSRF via LLM-Controlled Parameters
slug: 2026-08-contentful-mcp-ssrf
description: The Contentful MCP tools 'export_space' and 'import_space' are vulnerable to Server-Side Request Forgery (SSRF) due to the unsafe passing of LLM-controlled 'host' and 'proxy' arguments directly to the Contentful Management API client, enabling credential exfiltration.
date: "2026-08-19T22:34:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - llm-security
  - credential-theft
  - mcp
vendors:
  - Contentful
products:
  - Contentful MCP Tools
  - Contentful MCP Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An attacker who can invoke MCP tools, or inject instructions into Contentful content the LLM reads, can redirect all CMA requests
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attacker publishes Contentful entry... LLM reads the entry (get_entry), infers tool calls
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2xhg-73j7-rrgx
---

The Contentful MCP tools package (`@contentful/mcp-tools`) contains a critical vulnerability in the `export_space` and `import_space` functions that allows for Server-Side Request Forgery (SSRF). The vulnerability arises because these tools accept `host` and `proxy` parameters directly from LLM-controlled input and merge them into the configuration object for the Contentful Management API (CMA) SDK. 

Crucially, while the `createClientConfig` utility correctly extracts only the `accessToken` for authentication, the subsequent configuration merging logic persists the user-supplied `host` and `proxy` values. When the CMA SDK processes these options, it uses the malicious `host` to construct the base URL for API requests, while automatically attaching the server's legitimate Personal Access Token (PAT) as an `Authorization: Bearer` header. This allows an attacker to redirect internal CMA API calls to an attacker-controlled endpoint, effectively stealing the server's authentication credentials. This vector is accessible via direct MCP tool invocation or through prompt injection in content managed by Contentful.

## Attack Chain

1. Attacker discovers that the MCP server exposes `export_space` and `import_space` tools (potentially via `list_tools`).
2. Attacker crafts a prompt injection payload or direct MCP tool call to invoke `space_to_space_migration_handler` with the argument `{ "action": "enable" }`.
3. The handler elevates the privileges of the migration tools, transitioning `export_space` and `import_space` from a disabled to an enabled state.
4. Attacker executes `export_space` via the LLM, providing a malicious `host` (e.g., `attacker-controlled-server.com`) and setting `insecure: true` to force non-encrypted transit.
5. The tool merges the provided `host` parameter into the `exportOptions` object alongside the legitimate `managementToken`.
6. The `contentful-export` module passes the merged configuration to the `contentful-management` SDK.
7. The SDK initializes a client instance using the attacker-provided `baseURL`, effectively overriding the default Contentful API endpoint.
8. The SDK initiates an API request (e.g., to `/spaces/`) to the attacker-controlled server, including the `Authorization: Bearer <SERVER_PAT>` header, resulting in credential exfiltration.

## Impact

Successful exploitation allows an attacker to intercept the server's Personal Access Token (PAT). With this token, the attacker gains full management access to the victim's Contentful spaces and content, including the ability to read, modify, or delete sensitive data, and potentially pivot to other integrations linked to the account. This vulnerability affects Contentful MCP Tools versions below 0.4.2 and Contentful MCP Server versions below 1.7.16.

## Recommendation

* Update `@contentful/mcp-tools` to version 0.4.2 or higher and `@contentful/mcp-server` to 1.7.16 or higher immediately.
* Implement strict input validation on MCP tool arguments within the server, specifically ensuring that `host` and `proxy` parameters are restricted to an allowlist of known Contentful API endpoints.
* Audit logs for MCP tool calls where the `host` parameter deviates from the expected `api.contentful.com` or `cdn.contentful.com` domains.
* Revoke and rotate any Personal Access Tokens (PATs) that may have been exposed through this vulnerable function if suspicious outgoing connections were detected from the MCP server host.
