---
title: 9router Unauthenticated Remote Code Execution via MCP Plugin Routes
slug: 2026-05-9router-rce
description: 9router versions 0.4.30 to 0.4.33 are vulnerable to unauthenticated remote code execution, allowing network-adjacent attackers to execute arbitrary OS commands by registering and triggering malicious plugins through unprotected API endpoints.
date: "2026-05-19T19:22:37Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - unauthenticated
  - plugin
vendors:
  - 9router
products:
  - 9router (>= 0.4.30, < 0.4.37)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
references:
  - https://github.com/advisories/GHSA-fhh6-4qxv-rpqj
rules:
  - title: Detect 9router Unauthenticated RCE via MCP Plugin Registration
    description: Detects CVE-2026-46339 exploitation — Unauthenticated registration of custom plugins with potentially malicious commands in 9router via the /api/cli-tools/cowork-settings endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect 9router Unauthenticated RCE via MCP Plugin Execution
    description: Detects CVE-2026-46339 exploitation — Unauthenticated execution of custom plugins in 9router via the /api/mcp/[plugin]/sse endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
rules_count: 2
---

9router versions 0.4.30 through 0.4.33 are susceptible to an unauthenticated remote code execution vulnerability due to insufficient access control on the `/api/cli-tools/*` and `/api/mcp/*` API endpoints. Introduced in commit `8f4d29c` on 2026-05-11 with the addition of the MCP stdio→SSE bridge feature, this flaw allows a network-adjacent attacker to register a malicious plugin containing arbitrary OS commands. These commands can then be executed by triggering a Server-Sent Events (SSE) endpoint, resulting in the execution of commands as the user running the 9router process. This vulnerability poses a significant risk, as it requires no authentication and can be exploited in under 2 seconds from the first request.

## Attack Chain

1. The attacker sends a POST request to the `/api/cli-tools/cowork-settings` endpoint to register a malicious plugin. This endpoint is not protected by the Next.js middleware.
2. The POST request contains a JSON payload with a `customPlugins` array. The `name`, `command`, and `args` fields within the plugin definition are attacker-controlled.
3. The server-side code in `src/app/api/cli-tools/cowork-settings/route.js` extracts the `command` and `args` from the JSON payload without proper validation.
4. The extracted `command` and `args` are then stored in the `globalThis.__9routerCustomPlugins` map using the `registerCustomPlugin` function in `src/lib/mcp/stdioSseBridge.js`.
5. The attacker sends a GET request to the `/api/mcp/[plugin]/sse` endpoint, where `[plugin]` is the name of the malicious plugin registered in the previous steps.
6. The server-side code in `src/app/api/mcp/[plugin]/sse/route.js` retrieves the plugin definition from the `globalThis.__9routerCustomPlugins` map using the provided plugin name.
7. The `spawn` function in `src/lib/mcp/stdioSseBridge.js` is called with the attacker-controlled `command` and `args` from the plugin definition.
8. The arbitrary OS command is executed on the server, allowing the attacker to perform actions such as writing files, establishing reverse shells, or exfiltrating sensitive data.

## Impact

Successful exploitation of CVE-2026-46339 allows an unauthenticated attacker to achieve remote code execution on the 9router server. This can lead to full read access to the server's filesystem, including sensitive files such as API keys, TLS private keys, Anthropic tokens (`~/.claude/settings.json`), and AWS credentials (`~/.aws/credentials`, `~/.aws/sso/cache/*.json`). Attackers can also achieve arbitrary file write, persistence via cron/systemd, process termination, and resource exhaustion. The `docker` group membership may allow container escape leading to host root access.

## Recommendation

*   Apply the provided remediation steps by patching the `src/proxy.js` file to extend the middleware matcher to include `/api/cli-tools/:path*` and `/api/mcp/:path*` to prevent unauthenticated access.
*   Implement input validation and sanitization for the `command` and `args` fields in the `registerCustomPlugin` function in `src/lib/mcp/stdioSseBridge.js` to prevent execution of arbitrary commands.
*   Sanitize the `customPlugins` at the API boundary in `src/app/api/cli-tools/cowork-settings/route.js` to ensure that only authorized commands are executed.
*   Deploy the Sigma rule "Detect 9router Unauthenticated RCE via MCP Plugin Registration" to identify attempts to register malicious plugins via the `/api/cli-tools/cowork-settings` endpoint.
