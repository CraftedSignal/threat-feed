---
title: Unbounded Recursion Depth in Elixir Protobuf Decoder Causes Denial of Service
slug: 2026-07-protobuf-unbounded-recursion-dos
description: An unauthenticated attacker can trigger a denial-of-service condition in services that decode untrusted protobuf messages using the `Protobuf.Decoder` (Hex package `protobuf`) versions between 0.8.0 and 0.16.1 by crafting deeply nested self-referential message types, leading to memory exhaustion and service crashes.
date: "2026-07-15T17:45:25Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - elixir
  - protobuf
vendors:
  - elixir-protobuf
products:
  - protobuf (< 0.16.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Denial of Service
    technique_id: T1499
    technique_name: Resource Exhaustion
    evidence: unbounded recursion depth ... lets an unauthenticated attacker crash any service ... exhausting memory and pinning a scheduler.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-rv48-qqj5-crxg
  - https://github.com/elixir-protobuf/protobuf/commit/21ec7c5bec4fec74e10c1de0d5d1a2d8152ac5d4
  - https://github.com/elixir-protobuf/protobuf/commit/b8efa97790eece3d2d0e8e7c31a45ed409fe5338
---

CVE-2026-54451 describes a high-severity vulnerability involving unbounded recursion depth in the `Protobuf.Decoder` component of the Elixir `protobuf` Hex package, affecting versions `>= 0.8.0` and `< 0.16.1`. An unauthenticated attacker can exploit this flaw to launch a denial-of-service attack against any Elixir service that decodes untrusted Protobuf messages, particularly those with self-referential or cyclic message types in their schema. By sending a small, specially crafted Protobuf message (a few KB to MB) containing deeply nested fields, the attacker forces the BEAM runtime to recurse millions of times without a depth limit. This leads to severe memory exhaustion, excessive CPU consumption, and scheduler pinning, effectively rendering the victim service unresponsive or causing it to crash. The lack of a recursion-depth counter, unlike reference Protobuf implementations, makes the `protobuf` library vulnerable to request-amplification DoS attacks.

## Attack Chain

1. An attacker identifies an Elixir service that utilizes the vulnerable `protobuf` Hex package (versions between 0.8.0 and 0.16.1) to decode untrusted Protobuf input.
2. The attacker determines or defines a self-referential Protobuf message schema (e.g., `message Tree { Tree child = 1; }`) that the target application is configured to decode.
3. The attacker crafts a malicious Protobuf message in wire format, recursively nesting the self-referential field hundreds of thousands to millions of times.
4. The crafted message is optimized to be small in overall size (e.g., a few KB to a few MB) to maximize recursion depth while minimizing bandwidth consumption for the attacker.
5. The attacker sends the malicious message via an HTTP POST request with `Content-Type: application/x-protobuf` to an endpoint that processes and calls `Tree.decode/1` on the input.
6. The vulnerable `Protobuf.Decoder.value_for_field/3` function is invoked and recursively calls `decode` for each nested level without enforcing any depth limit.
7. Each recursive call consumes a new stack frame and allocates heap memory, leading to rapid exhaustion of process memory and significant CPU load on the BEAM runtime.
8. The victim service experiences a denial of service, becoming unresponsive or crashing, particularly if multiple concurrent requests are processed.

## Impact

This vulnerability (CVE-2026-54451) allows an unauthenticated, network-reachable attacker to perform a request-amplification denial-of-service against any Elixir service that decodes untrusted Protobuf messages containing self-referential or cyclic types. A single small, maliciously crafted request can consume seconds of CPU time and hundreds of megabytes of memory on the victim server. Just a few concurrent requests can lead to complete service unavailability or node crashes, severely impacting the reliability and accessibility of affected applications.

## Recommendation

* Patch CVE-2026-54451 immediately by updating the `protobuf` Hex package to version `0.16.1` or higher to ensure the recursion depth limit is enforced.
* Review webserver access logs and HTTP proxy logs for POST requests containing `Content-Type: application/x-protobuf` with unusually large `Content-Length` headers, which may indicate attempted exploitation.
* Implement robust application-level logging to capture `Protobuf.DecodeError` exceptions, as these indicate attempts to trigger or successful exploitation of recursion limits.
* Monitor Elixir BEAM node resources, specifically CPU utilization, memory consumption, and process stack depth, for sudden spikes or sustained high usage that could indicate a denial-of-service attack.
