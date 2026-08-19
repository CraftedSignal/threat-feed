---
title: Unbounded Memory Growth in MCP PHP SDK SSE Client
slug: 2026-08-mcp-sdk-sse-dos
description: The MCP PHP SDK's HTTP transport fails to bound the in-memory buffer used for Server-Sent-Events, allowing a malicious server to trigger a denial-of-service via memory exhaustion.
date: "2026-08-19T22:34:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - sse
  - mcp
  - memory-exhaustion
vendors:
  - MCP
products:
  - sdk (<= 0.5.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: |-
      An attacker controlling the remote SSE server endpoint can send a continuous stream of data without providing the required '

      ' event delimiter, causing the client to append incoming chunks indefinitely until it exhausts the PHP memory limit.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-7m52-jw36-44r3
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Update mcp/sdk to the latest version once a patch is released.
      owner: Development
      due: 72h
      evidence: Source provides a suggested fix via constant-based buffer limiting.
  mitigation_plan:
    - priority: short_term
      action: Restrict memory_limit for PHP processes handling external MCP connections.
      owner: IT Operations
      addresses: Memory exhaustion vulnerability
      evidence: Advisory confirms OOM-killer/fatal error trigger based on memory_limit.
---

The `mcp/sdk` library, specifically the `HttpTransport` class in version 0.5.0, contains a vulnerability where incoming Server-Sent-Events (SSE) chunks are appended to an internal `$sseBuffer` without any length validation. The implementation relies exclusively on the presence of the `"\n\n"` delimiter to flush and clear the buffer. An attacker in control of the remote MCP server endpoint, or an actor capable of performing a man-in-the-middle attack on a plaintext connection, can withhold the required delimiter while streaming arbitrary data. This forces the client to continuously allocate memory to hold the accumulating response, eventually causing the process to reach its PHP `memory_limit` or triggering an OS-level OOM (Out-of-Memory) event. This vulnerability effectively allows a malicious or compromised MCP server to crash any connected client.

## Attack Chain

1. The victim client initializes an `Mcp\Client\Transport\HttpTransport` instance to communicate with an adversarial MCP server.
2. The client initiates an SSE connection to the server endpoint.
3. The server begins streaming the response but deliberately omits the SSE `"\n\n"` event delimiter.
4. The client's `HttpTransport::processSSEStream()` method is invoked in a loop, reading 4096-byte chunks from the active stream.
5. The library appends each incoming chunk directly to the private `$sseBuffer` string.
6. Because the buffer is only flushed upon identifying `"\n\n"` via `strpos`, the internal buffer grows monotonically with every network read.
7. The client process consumes heap memory until exceeding the configured PHP `memory_limit` or system-available RAM.
8. The client crashes with a fatal memory exhaustion error, resulting in a successful denial-of-service.

## Impact

Successful exploitation results in the immediate denial-of-service of the client process. Any system or application relying on the `mcp/sdk` client is vulnerable to process crashes initiated by a malicious remote peer. This can lead to significant service disruption, especially in automated environments where the client is expected to maintain long-running connections to MCP servers.

## Recommendation

- Upgrade to a patched version of `mcp/sdk` that implements a hard limit on the SSE buffer size.
- If an immediate update is not available, implement a wrapper or middleware to monitor memory usage for MCP client processes and proactively terminate connections that exhibit anomalous memory growth.
- Ensure that all MCP connections are configured to use TLS to prevent man-in-the-middle injection of malicious SSE streams.
- Review and tighten the `memory_limit` configuration for PHP processes interacting with untrusted external servers to limit the impact of such memory-based exhaustion attacks.
