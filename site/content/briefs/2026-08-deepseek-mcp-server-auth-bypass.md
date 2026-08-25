---
title: Cross-Session Data Exposure and Authorization Bypass in deepseek-mcp-server
slug: 2026-08-deepseek-mcp-server-auth-bypass
description: An insecure global SessionStore implementation in deepseek-mcp-server versions 1.4.2 through 1.6.9 allows unauthorized callers to enumerate and manipulate other users' conversation contexts via the HTTP transport.
date: "2026-08-25T18:48:41Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Arikusi
products:
  - deepseek-mcp-server (1.4.2 to 1.6.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: An attacker can enumerate active session IDs via deepseek_sessions, then reuse a victim-controlled session_id in deepseek_chat to retrieve and continue the victim's conversation context.
    confidence_band: high
cves:
  - id: CVE-2026-55604
    cvss: 8.6
    epss: 0.00372
references:
  - https://github.com/advisories/GHSA-fh3r-g96v-f578
  - https://github.com/arikusi/deepseek-mcp-server/security/advisories/GHSA-fh3r-g96v-f578
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch deepseek-mcp-server to version 1.7.0
      owner: IT Operations
      due: 24h
      evidence: Fixed in 1.7.0. The HTTP transport's SessionStore is no longer a process-wide singleton.
  mitigation_plan:
    - priority: immediate
      action: Disable HTTP transport and default to STDIO
      owner: IT Operations
      addresses: CVE-2026-55604
      evidence: If upgrading is not immediately possible, run in STDIO transport (unset TRANSPORT=http) or stop the HTTP server.
---

The `deepseek-mcp-server` package, specifically when configured for HTTP transport, contains a critical authorization vulnerability (CVE-2026-55604) that leads to cross-session data exposure. The vulnerability stems from a process-global `SessionStore` implementation that fails to bind session identifiers to specific, authenticated transport sessions. Because the server treats user-supplied `session_id` strings as globally accessible keys, any client connected to the HTTP server can enumerate existing session IDs via the `deepseek_sessions` tool and subsequently interact with those sessions using the `deepseek_chat` tool.

This flaw effectively bypasses tenant isolation, permitting an attacker to read the conversation history of other users, inject new messages into ongoing conversations, or clear existing sessions. This issue affects versions 1.4.2 through 1.6.9. It does not impact the STDIO transport mode, as each STDIO connection runs in an isolated process.

## Attack Chain

1. The attacker connects to the `deepseek-mcp-server` instance over the HTTP transport.
2. The attacker calls the `deepseek_sessions` tool with an action parameter of 'list' to enumerate all currently active session IDs in the global store.
3. The server responds with a list of active `session_id` values, including those belonging to other connected users.
4. The attacker selects a target `session_id` from the enumerated list.
5. The attacker executes the `deepseek_chat` tool, providing the target `session_id` as an input parameter.
6. The `deepseek_chat` implementation in `src/tools/deepseek-chat.ts` loads the victim's conversation history associated with the supplied ID.
7. The attacker's new prompt is appended to the victim's existing conversation context and sent to the LLM backend.
8. The final assistant response is stored back into the victim's session, effectively poisoning or hijacking the conversation flow.

## Impact

The vulnerability allows for complete compromise of conversation privacy and integrity for all users connected to a multi-client HTTP instance of the server. Attackers can perform unauthorized data exfiltration of chat logs, influence the context of ongoing sessions, and perform denial-of-service by clearing session state. The number of impacted organizations is potentially high, given the use of MCP servers in collaborative AI development environments.

## Recommendation

1. Immediately upgrade `arikusi/deepseek-mcp-server` to version 1.7.0 or later to ensure proper session store isolation.
2. For environments where upgrading is not immediately feasible, disable the HTTP transport by unsetting the `TRANSPORT` environment variable to force the use of the unaffected STDIO transport.
3. Audit MCP server access logs to identify anomalous enumeration activity, specifically frequent requests to `deepseek_sessions` followed by rapid interactions with `deepseek_chat` using varying session identifiers.
4. Implement network-level access controls to restrict exposure of the HTTP-based MCP server instance to trusted clients only.
