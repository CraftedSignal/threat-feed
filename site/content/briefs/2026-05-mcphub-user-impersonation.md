---
title: MCPHub User Impersonation Vulnerability via Unauthenticated SSE Endpoint
slug: 2026-05-mcphub-user-impersonation
description: MCPHub is vulnerable to user identity spoofing on the MCP transport layer; an unauthenticated network user can impersonate any user, including administrators, on SSE/MCP endpoints by providing the target username in the URL path, which allows execution of MCP tool calls under a spoofed user's identity, access to user-scoped resources and data, and poisoning of audit logs.
date: "2026-05-14T20:45:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - identity-spoofing
  - sse
  - mcp
  - unauthenticated-access
vendors:
  - samanhappy
products:
  - '@samanhappy/mcphub (< 0.12.15)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://github.com/advisories/GHSA-wf8q-wvv8-p8jf
rules:
  - title: Detect MCPHub User Impersonation via SSE Endpoint
    description: Detects MCPHub user impersonation vulnerability exploitation by monitoring HTTP requests to the SSE endpoint with suspicious usernames.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect MCPHub MCP Tool Call via Spoofed User
    description: Detects MCPHub MCP tool call execution under a spoofed user, potentially indicating exploitation of the user impersonation vulnerability.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

MCPHub is vulnerable to a critical identity spoofing vulnerability that allows any unauthenticated user to impersonate any other user, including administrators, on SSE and MCP transport endpoints. This vulnerability exists because the server accepts a username directly from the URL path parameter without any database validation, token verification, or authentication check. The `sseUserContextMiddleware` in `src/middlewares/userContext.ts` extracts the username from `req.params.user` and constructs a fabricated `IUser` object, bypassing all authentication. This allows attackers to execute MCP tool calls under the spoofed user's context, access user-scoped resources and data, and poison audit logs. All MCPHub instances exposing SSE endpoints without bearer authentication are affected. This includes the default configuration when bearer keys are not explicitly set up. The vulnerability affects MCPHub versions prior to 0.12.15.

## Attack Chain

1. The attacker crafts a malicious URL containing the username of the target user within the path, for example `/CEO-admin-impersonated/sse`.
2. The attacker sends an HTTP GET request to the crafted URL targeting the `/sse` endpoint.
3. The `sseUserContextMiddleware` extracts the username directly from `req.params.user` without any authentication or validation.
4. The middleware constructs a fabricated `IUser` object with the spoofed username and sets it in the `UserContextService`.
5. The `handleSseConnection` function is called, establishing an SSE connection under the context of the spoofed user.
6. The attacker crafts an HTTP POST request to the `/messages` endpoint associated with the SSE session, including the session ID obtained during the SSE connection establishment.
7. The attacker includes a JSON payload in the POST request specifying the `tools/call` method and the desired tool and arguments.
8. The MCP tool is executed on the server under the context of the spoofed user, potentially granting unauthorized access to resources and data.

## Impact

This vulnerability enables a complete user identity spoofing on the MCP transport layer. Any unauthenticated network user can impersonate any other user, including administrators, on SSE/MCP endpoints. The attacker can then execute MCP tool calls under a spoofed user's identity, potentially accessing user-scoped resources and data. Furthermore, all actions are recorded under the fabricated username, destroying accountability and forensic value. All MCPHub instances exposing SSE endpoints without bearer authentication are affected.

## Recommendation

*   Deploy the `Detect MCPHub User Impersonation via SSE Endpoint` Sigma rule to your SIEM to detect exploitation attempts by monitoring HTTP requests to the SSE endpoint with suspicious usernames.
*   Deploy the `Detect MCPHub MCP Tool Call via Spoofed User` Sigma rule to your SIEM to detect exploitation attempts by monitoring HTTP requests with a spoofed user.
*   Upgrade to @samanhappy/mcphub version 0.12.15 or later to patch the vulnerability.
