---
title: MCP Python SDK Authentication Bypass Vulnerability (CVE-2026-52869)
slug: 2026-07-mcp-python-sdk-auth-bypass
description: A high-severity authentication bypass vulnerability, CVE-2026-52869, exists in affected versions of the MCP Python SDK's HTTP transports, allowing an attacker who obtains or guesses a session ID to send JSON-RPC messages to an existing session without verifying the authenticated principal, thereby bypassing per-client isolation and potentially injecting messages.
date: "2026-07-16T19:59:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - authentication-bypass
  - python
  - sdk
  - web-application
vendors:
  - MCP
products:
  - MCP Python SDK <= 1.27.1
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Anyone who learned or guessed a session ID could send JSON-RPC messages on that session, regardless of which bearer token the request carried.
    confidence_band: high
cves:
  - id: CVE-2026-52869
    cvss: 7.1
    epss: 0.00251
references:
  - https://github.com/advisories/GHSA-jpw9-pfvf-9f58
---

A significant authentication bypass vulnerability, identified as CVE-2026-52869, has been discovered in the MCP Python SDK versions up to 1.27.1. This flaw specifically impacts application servers using either the SSE (`mcp.server.sse.SseServerTransport`) or Streamable HTTP (`mcp.server.streamable_http_manager.StreamableHTTPSessionManager`) transports in stateful mode, particularly when authentication is configured. The vulnerability stems from the transports routing incoming requests to an existing session based solely on the session identifier (a query parameter or header), without validating that the request originates from the same authenticated principal who initially created the session. This oversight allows an attacker who can acquire or guess a session ID to inject unauthorized JSON-RPC messages into an active session, effectively bypassing the per-client isolation intended by authentication. The SSE transport has been affected since its initial release, while the Streamable HTTP transport became vulnerable in version 1.8.0.

## Attack Chain

1. **Initial Reconnaissance**: The attacker identifies a target application server utilizing the MCP Python SDK with HTTP transports (SSE or Streamable HTTP) and configured authentication.
2. **Session ID Acquisition**: The attacker obtains an active session ID for a legitimate user through out-of-band means such as sniffing network traffic, log compromise, or brute-forcing (session IDs are UUIDs, making brute-force difficult but not impossible).
3. **Crafting Malicious Request**: The attacker crafts a request containing malicious JSON-RPC messages, including the obtained legitimate `session_id` (for SSE) or `Mcp-Session-Id` header (for Streamable HTTP).
4. **Authentication Bypass**: The attacker sends the malicious request to the vulnerable server. The server routes the request to the target session solely based on the session ID, bypassing principal authentication checks.
5. **Message Injection**: The server processes the attacker's JSON-RPC messages within the context of the legitimate user's session, despite the request carrying a different or invalid bearer token.
6. **Impact on Session**: The injected messages can alter the session state, perform unauthorized actions, or exfiltrate sensitive information, depending on the application's functionality.
7. **Response Delivery**: For SSE, the response to the injected message is delivered to the original legitimate client's event stream. For Streamable HTTP, the injecting client receives the response directly.
8. **Achieve Objective**: The attacker successfully compromises session integrity, leading to unauthorized data manipulation or access, bypassing the intended per-client isolation.

## Impact

If successfully exploited, CVE-2026-52869 allows an attacker to bypass critical per-client isolation mechanisms provided by authentication in application servers using the MCP Python SDK's HTTP transports. This means that an attacker, upon obtaining a valid session ID, can inject arbitrary JSON-RPC messages into another user's active session. The direct consequence is unauthorized access and potential manipulation of session-dependent data or functionality. While session IDs are randomly generated UUIDs, making blind guessing difficult, any out-of-band leakage (e.g., via logs, network observation, or cross-site scripting) would enable exploitation. The impact could range from data corruption or unauthorized information disclosure to complete account compromise, depending on the privileges associated with the compromised session and the capabilities of the JSON-RPC interface.

## Recommendation

* Upgrade the `pip/mcp` package to version 1.27.2 or later immediately to address CVE-2026-52869.
* Ensure that, for deployments where many end users share a single OAuth client, the token verifier populates `AccessToken.subject` (e.g., from the token's `sub` claim) to enforce per-user session isolation.
* Review custom authentication backends, if used, to ensure they enforce equivalent principal verification checks as introduced in MCP Python SDK 1.27.2.
