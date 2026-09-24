---
title: Cross-Origin WebSocket Hijacking in Cline Hub Dashboard
slug: 2026-09-cline-cswsh
description: The Cline Hub dashboard fails to validate Origin headers and bypasses authorization when no secret is configured, allowing malicious websites to hijack local WebSocket connections to execute arbitrary code.
date: "2026-09-24T20:04:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - remote-code-execution
  - websocket-hijacking
vendors:
  - Cline
products:
  - cline-hub
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: A malicious website visited by a user running the Cline dashboard can establish a WebSocket connection to the local server.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The server processes the frame and writes a malicious stdio MCP server entry to settings, achieving persistent code execution when Cline activates the MCP server.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - SOC
  immediate_actions:
    - action: Review local developer environments for instances of cline-hub running without ROOM_SECRET
      owner: SOC
      due: 24h
      evidence: Source document identifies missing ROOM_SECRET as the primary authorization bypass condition.
  mitigation_plan:
    - priority: immediate
      action: Mandate ROOM_SECRET environment variable for all cline dashboard deployments
      owner: IT Operations
      addresses: CSWSH vulnerability in cline-hub
      evidence: Source identifies setting the ROOM_SECRET as the mitigation for the authorization bypass.
---

The Cline Hub dashboard server ('@cline/cline-hub'), typically initiated via the `cline dashboard` CLI command, contains a critical security flaw involving Cross-Origin WebSocket Hijacking (CSWSH). In its default configuration, the dashboard binds to `127.0.0.1` without requiring a `ROOM_SECRET`. Under these conditions, the server's `isAuthorizedBrowserRequest()` function returns `true` for all requests and performs no validation of the HTTP `Origin` header during the WebSocket upgrade process.

This vulnerability allows any malicious website visited by a developer running the Cline dashboard to open a WebSocket connection to `ws://127.0.0.1:8787/browser`. Once connected, the attacker can interact with the Cline session as if they were a legitimate user. This includes the ability to inject malicious MCP server configurations, modify tool approval policies, and command agent sessions to perform unauthorized actions such as file system manipulation or arbitrary command execution on the host machine. Because dashboard sessions default to auto-approving tools, this process requires no victim interaction beyond simply visiting a compromised page.

## Attack Chain

1. The victim starts `cline dashboard` locally, which defaults to `127.0.0.1:8787` without a `ROOM_SECRET`.
2. The attacker lures the victim to a malicious website containing a cross-origin WebSocket payload.
3. The victim's browser initiates a WebSocket connection request to `ws://127.0.0.1:8787/browser`.
4. The Cline Hub dashboard server receives the request, identifies the missing secret, and unconditionally approves the connection, ignoring the `Origin` header.
5. The attacker's script sends a `desktopCommand` frame of type `upsert_mcp_server` over the established WebSocket.
6. The server processes the frame and writes a malicious `stdio` MCP server entry to `$CLINE_DATA_DIR/settings/cline_mcp_settings.json`.
7. Upon the next invocation or activation of the MCP server by the Cline agent, the injected command is executed with the privileges of the victim's local user account.

## Impact

Successful exploitation allows for full command execution on the developer's local machine, potential exfiltration of sensitive session tokens or API keys, and persistent compromise via the injection of malicious MCP server entries into the developer's configuration files. This impacts any environment where developers use the default dashboard settings, posing a significant risk to individual workstations and the local development ecosystem.

## Recommendation

1. Ensure that the `ROOM_SECRET` environment variable is always explicitly set for any instance of the Cline dashboard to enforce mandatory authentication.
2. Implement local firewall rules or browser security extensions to restrict WebSocket connections to `127.0.0.1` to authorized origins only.
3. Regularly audit `$CLINE_DATA_DIR/settings/cline_mcp_settings.json` for unexpected entries or suspicious `stdio` commands.
4. Avoid running the `cline dashboard` in environments where untrusted browser activity is expected.
