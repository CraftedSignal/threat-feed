---
title: '@anephenix/hub Unauthenticated WebSocket RPC Waiter Resource Exhaustion (CVE-None)'
slug: 2026-07-anephenix-hub-dos
description: An unauthenticated Denial-of-Service vulnerability in `@anephenix/hub` versions prior to 0.2.16 allows attackers to exhaust server CPU and memory resources by opening numerous WebSocket connections and ignoring server-initiated RPC messages, leading to unbounded timers and heap entries.
date: "2026-07-24T21:53:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - websocket
  - node.js
vendors:
  - anephenix
products:
  - '@anephenix/hub < 0.2.16'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated attacker who opens many WebSocket connections and ignores all server RPC messages will therefore cause the server to accumulate unbounded timers and heap entries, leading to CPU and memory exhaustion (DoS).
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-g5vv-q72c-7j78
---

A high-severity unauthenticated Denial-of-Service (DoS) vulnerability exists in the `@anephenix/hub` Node.js library, affecting all versions prior to 0.2.16. This flaw arises because the server initiates a `setInterval` polling loop and accumulates pending RPC request objects for every incoming WebSocket connection. Specifically, if a remote client fails to reply to the server's `get-client-id` RPC, these timers and corresponding request objects are never cleaned up, even after the WebSocket connection is terminated. An unauthenticated attacker can exploit this by establishing a large number of WebSocket connections and deliberately ignoring server RPC messages. This action causes the server to accumulate an unbounded number of `setInterval` timers and heap entries, leading to severe CPU and memory exhaustion and rendering the `@anephenix/hub` server unavailable to legitimate clients. The vulnerability does not require any authentication or specialized headers, making it easily exploitable.

## Attack Chain

1. An unauthenticated client establishes a WebSocket connection to the `@anephenix/hub` server.
2. The server's connection listener, registered in `src/lib/index.ts:128`, invokes `requestClientId` for the newly established WebSocket (`src/lib/index.ts:262`).
3. `requestClientId` then calls `rpc.send` to issue a `get-client-id` RPC request to the client (`src/lib/clientId.ts:112`).
4. The RPC request payload is pushed onto the server's `this.requests` array within `rpc.send` (`src/lib/rpc.ts:282`), marking it as a pending request.
5. Inside `rpc.send`, `waitForReply` is invoked, which starts a `setInterval` timer polling every 10 ms to check for a matching reply in the `responses[]` array (`src/lib/rpc.ts:250`).
6. The attacker's client deliberately ignores the server's `get-client-id` RPC message and then closes the WebSocket connection without sending any reply.
7. Due to the absence of a reply, the `setInterval` timer and the corresponding entry in `this.requests` are not cleared, leading to a resource leak within the server process.
8. The attacker repeats this process with numerous connections, causing an accumulation of unbounded timers and heap objects, ultimately leading to CPU and memory exhaustion and a Denial of Service.

## Impact

This is an unauthenticated Denial-of-Service (DoS) vulnerability affecting any network-reachable `@anephenix/hub` server running with default configurations. Exploitation allows an attacker to exhaust the server's CPU and memory resources by forcing it to accumulate an ever-increasing number of `setInterval` timers and heap entries. Each unanswered WebSocket connection contributes one `setInterval` timer (polling every 10 ms) and one heap object that is never released. As more connections are made and then silently dropped, the server's resource consumption spirals, leading to performance degradation and eventually making the server unresponsive or unavailable to legitimate clients. No complex authentication, headers, or protocol knowledge is required for successful exploitation.

## Recommendation

* Upgrade `@anephenix/hub` to version 0.2.16 or higher immediately to address the vulnerability.
* Monitor server resource utilization (CPU, memory) for `@anephenix/hub` instances to detect anomalous spikes that could indicate a DoS attack.
* Implement application-layer logging for WebSocket RPC requests and responses to track incomplete transactions that may indicate exploitation of this vulnerability.
