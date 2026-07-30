---
title: Uncontrolled Memory Allocation in MCP Ruby SDK
slug: 2026-07-mcp-ruby-oom
description: An unauthenticated remote attacker can cause a denial-of-service in MCP Ruby SDK servers by sending oversized JSON-RPC requests that trigger unbounded memory allocation.
date: "2026-07-30T15:30:16Z"
type: advisory
types:
  - advisory
severities:
  - low
vendors:
  - RubyGems
products:
  - mcp (<= 0.22.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated remote attacker can force any MCP Ruby SDK server using MCP::Server::Transports::StreamableHTTPTransport to allocate gigabytes of memory... allowing trivial denial of service against the worker process.
    confidence_band: high
cves:
  - id: CVE-2026-67432
    cvss: 7.5
    epss: 0.00436
references:
  - https://github.com/advisories/GHSA-h669-8m4g-r2hc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67432
---

The MCP Ruby SDK contains a vulnerability in the `StreamableHTTPTransport` and `StdioTransport` components that allows for trivial denial-of-service (DoS) via memory exhaustion. The vulnerability stems from the `handle_post` method, which reads the entire body of an incoming HTTP request into memory using `request.body.read` without any size constraints or pre-validation of the `Content-Length` header. Subsequently, the application calls `JSON.parse` with `symbolize_names: true` on the entire payload. Because `symbolize_names` creates a Ruby symbol for every JSON key, the memory consumption is significantly amplified beyond the raw size of the payload. This vulnerability is reachable without authentication, making it accessible to any unauthenticated remote attacker with network reach to the MCP server. Successfully sending a single large payload can drive a worker process to consume gigabytes of memory, leading to OOM-termination.

## Attack Chain

1. Attacker identifies an MCP Ruby SDK server exposing the `StreamableHTTPTransport` interface.
2. Attacker crafts a malicious JSON-RPC POST request with a large payload (e.g., several hundred megabytes).
3. Attacker sends the HTTP request to the target server's endpoint.
4. The `StreamableHTTPTransport` component receives the request and executes `request.body.read`.
5. The application loads the entirety of the attacker-supplied payload into a Ruby `String`.
6. The `JSON.parse` method executes on the full payload, creating a large object graph and numerous symbols.
7. The server process memory usage spikes dramatically, consuming system resources.
8. The worker process crashes or is terminated due to OOM (Out of Memory) conditions, resulting in denial-of-service.

## Impact

The vulnerability allows any unauthenticated attacker with network access to crash individual worker processes of an MCP Ruby SDK application. By repeatedly sending these malicious requests, an attacker can maintain a persistent DoS state. In multi-tenant environments, this vulnerability enables an attacker to starve shared server resources, potentially impacting services running alongside the vulnerable worker.

## Recommendation

Prioritized actions for mitigation:
- Upgrade the `mcp` gem to a version containing the patch for CVE-2026-67432 once available.
- Implement an inbound request size limit at the reverse proxy or web server layer (e.g., Nginx `client_max_body_size`) to drop requests exceeding a reasonable threshold (e.g., 4 MiB) before they reach the Ruby application.
- Apply middleware in the Rack application to validate the `Content-Length` header before reading the request body.
- Configure the application to use a streaming JSON parser rather than loading the full request body into memory.
