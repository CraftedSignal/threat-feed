---
title: flyto-core Unauthenticated Command Execution via HTTP MCP `execute_module`
slug: 2026-07-flyto-core-unauthenticated-rce
description: flyto-core is vulnerable to unauthenticated command execution via its HTTP MCP endpoint (`POST /mcp`), allowing remote attackers to execute arbitrary OS commands with server privileges by invoking `sandbox.execute_shell` through JSON-RPC requests, potentially leading to full system compromise.
date: "2026-07-06T17:45:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - unauthenticated-rce
  - command-injection
  - web-application
  - ghsa
  - linux
vendors:
  - flytohub
products:
  - flyto-core 2.26.2
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The HTTP MCP endpoint (`POST /mcp`) in flyto-core accepts unauthenticated JSON-RPC `tools/call` requests
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: '`sandbox.execute_shell`, which passes attacker-controlled input directly to `asyncio.create_subprocess_shell`.'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-h9f9-h6gm-wc85
rules:
  - title: Detect flyto-core Unauthenticated MCP Endpoint Access
    description: Detects unauthenticated HTTP POST requests to the /mcp endpoint of flyto-core, indicating potential exploitation of the unauthenticated command execution vulnerability.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

flyto-core, an application leveraging FastAPI, is susceptible to an unauthenticated command execution vulnerability. This flaw exists within its HTTP MCP endpoint (`POST /mcp`), which lacks proper authentication and authorization checks. Discovered on 2026-07-06, the vulnerability allows unauthenticated attackers to send JSON-RPC `tools/call` requests that are then dispatched to arbitrary internal modules, including `sandbox.execute_shell`. This specific module executes attacker-controlled input directly via `asyncio.create_subprocess_shell` with `shell=True`, bypassing security controls. By default, flyto-core binds to `127.0.0.1`, making it a high-severity local vulnerability (CVSS 8.4); however, if configured to bind to `--host 0.0.0.0`, it becomes remotely exploitable, enabling full system compromise with root privileges as demonstrated in dynamic reproductions.

## Attack Chain

1.  Attacker sends an unauthenticated HTTP POST request to the `/mcp` endpoint of a vulnerable flyto-core server.
2.  The `mcp_router` (mounted at `src/core/api/server.py:75-78`) receives the request without requiring authentication.
3.  The `mcp_post` function (`src/core/api/routes/mcp.py:65-66`) processes the request body, which is an attacker-controlled JSON-RPC payload.
4.  The `handle_jsonrpc_request` function (`src/core/api/routes/mcp.py:103-104`) forwards the JSON-RPC item containing a `tools/call` method with `name: execute_module` and `module_id: sandbox.execute_shell` to the module dispatcher.
5.  The module registry (`src/core/mcp_handler.py:180`) resolves `sandbox.execute_shell` and invokes it with attacker-supplied `params`, including a `command` argument.
6.  The `sandbox.execute_shell` module (`src/core/modules/atomic/sandbox/execute_shell.py:137-139`) extracts the `command` directly from `params` without sanitization.
7.  The `command` is passed to `asyncio.create_subprocess_shell` with `shell=True` (`src/core/modules/atomic/sandbox/execute_shell.py:163-169`).
8.  The flyto-core server process executes the arbitrary OS command supplied by the attacker, with the privileges of the server.

## Impact

This unauthenticated command execution vulnerability carries critical impact. Any local process can exploit the vulnerability if `flyto serve` is running on a workstation, leading to arbitrary file operations, credential exfiltration, or lateral movement. More severely, if `flyto-core` is exposed externally (e.g., bound to `0.0.0.0`), unauthenticated remote attackers can achieve full system compromise with `root` privileges, as confirmed by dynamic reproduction. The vulnerability affects developers and local users running the service, as well as infrastructure operators who expose the API without proper network-level access controls. Consequences include complete host takeover.

## Recommendation

*   Deploy the provided Sigma rule to detect unauthenticated POST requests to `/mcp`.
*   Inspect webserver logs for HTTP POST requests to the `/mcp` URI as an indicator of attempted exploitation.
*   Patch affected flyto-core instances immediately by applying the recommended code changes from the source, specifically ensuring `require_auth` dependency for `/mcp` routes and adding `sandbox.*` to the `_DEFAULT_DENYLIST`.
