---
title: GitHub MCP Server Nil Pointer Dereference DoS in completion/complete Handler (CVE-2026-47427)
slug: 2026-07-github-mcp-server-dos
description: A nil pointer dereference vulnerability, tracked as CVE-2026-47427, in the GitHub MCP Server's `completion/complete` handler allows an unauthenticated attacker to cause a complete denial of service by sending a malformed JSON-RPC request with missing or empty parameters for the `ref` field, leading to an immediate server crash.
date: "2026-07-28T14:38:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - github
vendors:
  - GitHub
products:
  - github-mcp-server (< 1.1.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A nil pointer dereference vulnerability in the GitHub MCP Server causes it to crash when receiving a malformed `completion/complete` request with missing or empty parameters. This allows any unauthenticated client to cause a complete denial of service.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-w4q6-qw23-4rg7
---

A high-severity denial-of-service vulnerability, identified as CVE-2026-47427, has been discovered in the GitHub MCP Server. This flaw, specifically a nil pointer dereference, resides within the `CompletionsHandler` function (located at `pkg/github/server.go:198`) which is responsible for processing `completion/complete` JSON-RPC requests. Attackers can exploit this vulnerability without authentication by sending a crafted JSON-RPC message that either contains empty `params` or is missing the crucial `ref` field within the `params`. Upon receiving such a request, the server attempts to dereference a `nil` pointer, causing the Go runtime to panic and the MCP Server process to crash entirely. This vulnerability affects GitHub MCP Server versions prior to 1.1.0 and allows for a complete and unrecoverable denial of service by any unauthenticated client capable of sending JSON-RPC messages.

## Attack Chain

1. An unauthenticated attacker identifies a GitHub MCP Server instance accessible on the network.
2. The attacker establishes a connection and completes the necessary MCP initialization handshake with the server.
3. The attacker crafts a malformed JSON-RPC `completion/complete` request, intentionally omitting or emptying the `ref` parameter within the `params` object (e.g., `{"jsonrpc":"2.0","id":2,"method":"completion/complete","params":{}}`).
4. The attacker sends this crafted request to the vulnerable `/completion/complete` endpoint on the GitHub MCP Server.
5. The server's `CompletionsHandler` function receives the request and attempts to access `params.Ref` without first verifying if `params` or `params.Ref` is `nil`.
6. Due to the malformed request, `params.Ref` is `nil` at the point of access, leading to a nil pointer dereference.
7. The Go runtime detects the invalid memory access and triggers an immediate panic.
8. The GitHub MCP Server process crashes, resulting in a complete and unrecoverable denial of service for all connected clients.

## Impact

The successful exploitation of CVE-2026-47427 leads to an immediate and complete denial of service for the GitHub MCP Server. Any unauthenticated client capable of sending JSON-RPC messages can crash the server, making it unavailable to legitimate users. The panic caused by the nil pointer dereference is unrecoverable and terminates the server process, requiring manual intervention to restart. Automated fuzzing efforts demonstrated a significant crash rate (11.7% of test cases), indicating the ease with which this vulnerability can be triggered. Organizations using affected versions of GitHub MCP Server are at risk of significant service disruption and availability loss.

## Recommendation

* Patch affected GitHub MCP Server instances to version 1.1.0 or newer immediately to mitigate CVE-2026-47427.
* Configure webserver or API gateway logs to capture full request bodies for the `/completion/complete` endpoint to enable detection of malformed JSON-RPC requests as described in the attack chain.
* Deploy a Web Application Firewall (WAF) or API gateway capable of inspecting and blocking malformed JSON-RPC requests targeting the `/completion/complete` endpoint, specifically looking for empty or missing `ref` parameters.
