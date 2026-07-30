---
title: Session Poisoning Vulnerability in Ruby MCP SDK
slug: 2026-07-mcp-ruby-session-poisoning
description: The Ruby SDK for the Model Context Protocol (MCP) lacks session ownership validation, allowing attackers to perform unauthorized tool executions within a victim's active session.
date: "2026-07-30T15:30:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-67431
  - mcp
  - session-hijacking
  - ruby
  - sse
vendors:
  - Model Context Protocol
products:
  - Ruby SDK (<= 0.22.0)
cves:
  - id: CVE-2026-67431
    epss: 0.00276
references:
  - https://github.com/advisories/GHSA-5p9g-j988-pcwv
  - https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices#mitigation-4
  - https://github.com/modelcontextprotocol/ruby-sdk/security/advisories/GHSA-qvqr-5cv7-wh35
---

The Ruby SDK for the Model Context Protocol (MCP) is affected by a session ownership validation vulnerability (CVE-2026-67431) in its Streamable and Server-Sent Events (SSE) HTTP transport implementations. Versions up to and including 0.22.0 fail to cryptographically or logically bind session IDs to the user context that initialized them. This oversight allows an attacker who has obtained a valid session ID - through means such as network monitoring or log access - to perform unauthorized tool calls by sending POST requests to the `/messages/{session_id}` endpoint. The MCP server processes these requests as if they originated from the legitimate user, subsequently injecting the tool execution output directly into the victim's SSE stream. This silent manipulation allows for unauthorized state changes and data exfiltration while masquerading as legitimate traffic to the victim.

## Attack Chain

1. The victim initiates a legitimate MCP session with the server, receiving a unique session ID.
2. The attacker monitors network traffic or application logs to intercept the active session ID.
3. The attacker crafts a malicious POST request targeting the `/messages/{session_id}` endpoint.
4. The attacker includes a payload containing the unauthorized tool call to be executed by the server.
5. The server receives the attacker's POST request and fails to validate ownership of the provided session ID.
6. The server executes the malicious tool call within the context of the victim's session.
7. The server pushes the result of the unauthorized tool execution to the victim's active SSE response stream.
8. The victim receives the injected response, unaware that the action was initiated by an attacker.

## Impact

Successful exploitation allows attackers to perform unauthorized actions within an application, significantly compromising data integrity. The attack is stealthy, as the victim remains connected and receives legitimate-looking responses, masking the malicious tool executions occurring in their session. This vulnerability impacts all sectors utilizing the vulnerable Ruby SDK for MCP integration, potentially leading to unauthorized data exfiltration or state corruption depending on the capabilities exposed via MCP tools.

## Recommendation

Prioritize the upgrade of the `mcp` gem to a version that addresses CVE-2026-67431, which implements strict session ID binding. As a temporary mitigation, monitor web server access logs for anomalous POST requests to the `/messages/` endpoint that originate from IP addresses inconsistent with the original session initialization. Detection engineers should inspect HTTP logs for patterns where multiple distinct client IPs interact with the same unique session ID segment within the URI.
