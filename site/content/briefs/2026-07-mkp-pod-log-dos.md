---
title: MKP Pod Log Read Vulnerability Leads to Memory Exhaustion and Denial of Service
slug: 2026-07-mkp-pod-log-dos
description: An unauthenticated remote attacker can exploit a vulnerability in the MKP (Model Context Protocol for Kubernetes) server to exhaust its memory and cause a denial of service by sending a crafted `tools/call` request that manipulates `limitBytes` or `tailLines` parameters, leading to unbounded Kubernetes pod log reads into memory.
date: "2026-07-14T19:21:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - denial-of-service
  - memory-exhaustion
  - unauthenticated
  - mcp
  - cloud
vendors:
  - StacklokLabs
products:
  - MKP server
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This is an unauthenticated remote Denial of Service (DoS) vulnerability affecting any deployment of MKP server accessible over the network.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A remote unauthenticated attacker can exploit this to exhaust the MKP server's memory by sending a single crafted tools/call request, leading to process termination (OOM kill) and denial of service.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-qw5r-ppcg-f8rj
---

A critical vulnerability exists in the MKP (Model Context Protocol for Kubernetes) server, allowing an unauthenticated remote attacker to trigger a denial of service. The MKP server's `get_resource` MCP tool, which proxies Kubernetes pod log requests, improperly handles user-supplied `limitBytes` and `tailLines` parameters. These parameters are parsed as unbounded `int64` values and forwarded directly to the Kubernetes API. The server then reads the entire log stream into an in-memory buffer without application-side size limits. This design flaw enables an attacker to exhaust the server's memory, leading to an Out-of-Memory (OOM) kill and service unavailability. The vulnerability is present in the default configuration of `mkp-server` on port 8080 and requires no prior authentication or privileges. Proof-of-concept testing showed the MKP process RSS growing from 25.8 MB to 1,179.3 MB when handling a single request with `limitBytes=134217728`.

## Attack Chain

1. The MKP server listens on port 8080 by default without requiring authentication.
2. The `NewGetResourceTool()` is unconditionally registered, making the `get_resource` MCP tool available to unauthenticated users.
3. An unauthenticated attacker sends a crafted `tools/call` request via an HTTP POST to the `/mcp` endpoint, specifying `resource: "pods"` and `subresource: "logs"`.
4. Within the request parameters, the attacker supplies arbitrarily large `int64` string values for `limitBytes` (e.g., "2147483647") or `tailLines` (e.g., "999999999").
5. The MKP server processes these unbounded parameters without validation and forwards them to the Kubernetes API to retrieve pod logs.
6. The server then attempts to read the entire potentially massive log stream returned by the Kubernetes API directly into an in-memory `bytes.Buffer` using `io.Copy`, without any application-level size constraints.
7. This unbounded read rapidly consumes the MKP server's available memory, causing its Resident Set Size (RSS) to grow significantly.
8. The MKP server process eventually exhausts system memory, leading to an Out-of-Memory (OOM) termination and a denial of service for the entire MKP service.

## Impact

This is an unauthenticated remote Denial of Service (DoS) vulnerability that affects any deployment of the MKP server accessible over the network. Organizations running `mkp-server` in its default configuration are vulnerable, as no authentication or specific flags are required to exploit `get_resource`. Kubernetes clusters containing pods with large accumulated logs, such as `kube-system` workloads in production environments, are particularly susceptible. The success of this attack makes the entire MKP service unavailable, disrupting cluster observability and any downstream consumers relying on the MCP interface. A single crafted `tools/call` request with a sufficiently large `limitBytes` or `tailLines` value is enough to trigger the memory exhaustion, as the internal rate limiter only caps request frequency and not data volume.

## Recommendation

* Update the MKP server to a patched version that implements application-side limits for `limitBytes` and `tailLines` parameters as described in the provided remediation code.
* Restrict network access to the MKP server's default port 8080 from untrusted sources to reduce the attack surface.
* Monitor the MKP server process memory usage (RSS) for sudden, large increases or OOM events that deviate from normal operational baselines.
* Review web server or proxy logs for HTTP POST requests to the `/mcp` endpoint containing `tools/call` method with unusually large string values for `limitBytes` or `tailLines` in the JSON request body.
