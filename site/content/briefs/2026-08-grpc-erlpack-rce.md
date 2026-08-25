---
title: Critical RCE and DoS Vulnerability in Elixir gRPC Package
slug: 2026-08-grpc-erlpack-rce
description: The GRPC.Codec.Erlpack decoder in the Elixir gRPC package is vulnerable to unauthenticated remote code execution and node-level denial of service due to insecure deserialization of untrusted gRPC payloads.
date: "2026-08-25T18:48:23Z"
lastmod: "2026-08-25T18:49:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - denial-of-service
  - elixir
  - erlang
  - grpc
  - memory-exhaustion
vendors:
  - elixir-grpc
products:
  - grpc
  - grpc (>= 0.4.0, < 1.0.0)
  - grpc (>= 0.3.1, < 1.0.0)
  - grpc (>= 0.8.0, < 1.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: 'Any unauthenticated peer that can reach a gRPC endpoint with Content-Type: application/grpc+erlpack can... achieve remote code execution inside the server process.'
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated remote peer can crash any gRPC server built on this library by sending a small gzip-compressed frame that decompresses to gigabytes, exhausting the BEAM node's heap and triggering an OOM kill.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated attacker who can reach a transcoded endpoint can substitute any path-bound identifier with an arbitrary value, bypassing authorization, multi-tenancy, and ownership checks.
    confidence_band: high
cves:
  - id: CVE-2026-48853
    epss: 0.00573
references:
  - https://github.com/advisories/GHSA-grp7-v8xh-rj7h
  - https://github.com/elixir-grpc/grpc/commit/25bcc569fe2cc4478531a6c546c923205fc751c9
  - https://github.com/elixir-grpc/grpc/commit/272a97a5ea1b46af1819f14a831fcf35fc91f992
  - https://github.com/advisories/GHSA-6ccx-9c9f-327w
  - https://github.com/elixir-grpc/grpc/commit/beae6800fc8baf126f3fe7107d86a50e105275ba
  - CVE-2026-53430
  - https://github.com/advisories/GHSA-q8gf-9rvj-gmgj
  - https://github.com/elixir-grpc/grpc/commit/49e18c3ec6bb9afe2f712caad3dbab5c56a68a00
  - https://github.com/advisories/GHSA-mwr4-5g34-j5cq
  - https://github.com/elixir-grpc/grpc/commit/8aaf3d3a8c4c7b08ac65e9c6f254e0d24da1d048
  - https://github.com/elixir-grpc/grpc/commit/33b6a095dbc91c6dee3c7b90893d7d74952e82e4
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade grpc package to version 1.0.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source GHSA-grp7-v8xh-rj7h recommends upgrading to 1.0.0
  mitigation_plan:
    - priority: immediate
      action: Remove GRPC.Codec.Erlpack from registered server codecs
      owner: IT Operations
      addresses: CVE-2026-48853
      evidence: 'Configuration requirement: GRPC.Codec.Erlpack is not registered by default and must be explicitly added to the server''s codecs option.'
updates:
  - at: "2026-08-25T18:49:12Z"
    level: L1
    summary: added coverage for grpc (>= 0.4.0, < 1.0.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-6ccx-9c9f-327w
  - at: "2026-08-25T18:49:20Z"
    level: L1
    summary: added coverage for grpc (>= 0.3.1, < 1.0.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-q8gf-9rvj-gmgj
  - at: "2026-08-25T18:49:27Z"
    level: L2
    summary: added coverage for grpc (>= 0.8.0, < 1.0.0)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-mwr4-5g34-j5cq
---

The `grpc` package for Elixir (versions 0.4.0 through 0.9.x) contains a critical vulnerability in `GRPC.Codec.Erlpack.decode/2` that allows for unauthenticated remote code execution (RCE) and denial of service (DoS). The vulnerability stems from the use of `:erlang.binary_to_term/1` on raw gRPC message bodies without the mandatory `:safe` option. This function is used to deserialize data provided via the `application/grpc+erlpack` content type.

Because the deserialization process is unsafe, it permits the instantiation of arbitrary terms, including function objects (fun terms) and large numbers of atoms. An attacker can exploit this in two ways: by saturating the BEAM global atom table (which is capped at ~1 million entries) to crash the entire node, or by injecting serialized function terms that execute arbitrary code when subsequently invoked by the host application. This vulnerability is specific to environments where developers have explicitly registered `GRPC.Codec.Erlpack` in their gRPC server configuration.

## Attack Chain

1. Attacker identifies a target gRPC server that has explicitly configured `GRPC.Codec.Erlpack` as a codec.
2. Attacker establishes a standard HTTP/2 connection to the gRPC service endpoint.
3. Attacker constructs a malicious gRPC payload serialized via `:erlang.term_to_binary` containing a fun term for RCE or repeated atom definitions for DoS.
4. Attacker sends an HTTP POST request to the gRPC endpoint with the header `Content-Type: application/grpc+erlpack`.
5. The server's `GRPC.Codec.Erlpack.decode/2` function parses the request body and materializes the unsafe terms into the server process memory.
6. For DoS, the accumulated atoms exhaust the BEAM virtual machine's global atom table, resulting in a node-wide crash.
7. For RCE, the malicious fun term is passed to a downstream Elixir call site (such as `Enum.map` or `Task.async`).
8. The host application executes the attacker-controlled code within the context of the server process.

## Impact

Successful exploitation allows unauthenticated attackers to fully compromise the host server by executing arbitrary code with the privileges of the BEAM virtual machine process. Alternatively, attackers can force a complete denial of service by crashing the node through atom table exhaustion. This vulnerability affects any gRPC-based Elixir application that enables the Erlpack codec.

## Recommendation

Prioritize the immediate update of the `grpc` Elixir package to version 1.0.0 or later, which addresses this deserialization flaw. For environments that cannot immediately patch, remove `GRPC.Codec.Erlpack` from the list of registered codecs in your gRPC server configuration. Detection engineers should inspect server logs for any incoming requests utilizing the `application/grpc+erlpack` content type and verify if such usage is expected in the production environment.
