---
title: vLLM Remote Denial of Service via Invalid Token Reinjection
slug: 2026-07-vllm-dos
description: A frontend-legal multi-request speculative workload can cause vLLM to produce an out-of-vocabulary recovered token, which is then converted to an invalid value (-1) and reinjected into the drafting input IDs, leading to a GPU device-side assert and crashing the vLLM engine, causing a service-wide denial of service through a specific gRPC request sequence.
date: "2026-07-17T17:08:53Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:vllm:vllm:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - LLM
  - AI
  - python
  - server-side
vendors:
  - vLLM
products:
  - vLLM (>= 0.17.1, < 0.24.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A remote client that can send public gRPC generation requests can crash the shared vLLM engine worker
    confidence_band: high
cves:
  - id: CVE-2026-54234
    cvss: 7.5
    epss: 0.00343
references:
  - https://github.com/advisories/GHSA-8wr5-jm2h-8r4f
  - https://github.com/vllm-project/vllm/pull/44744
rules:
  - title: Detect vLLM Engine DoS via Invalid Token Reinjection (CVE-2026-54234)
    description: Detects CVE-2026-54234 exploitation - Detects the server-side crash messages indicating a Denial of Service due to CVE-2026-54234 exploitation in vLLM. This occurs when an invalid token leads to a GPU device-side assert, crashing the vLLM engine.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499
    data_sources:
      - logfile
      - linux
rules_count: 1
---

A critical vulnerability, tracked as CVE-2026-54234, affects vLLM versions 0.17.1 up to (but not including) 0.24.0. This flaw allows a remote client to trigger a denial of service (DoS) in the vLLM engine. The attack is initiated by sending a specific, frontend-legal multi-request speculative workload that causes the engine to generate an out-of-vocabulary token. This invalid token is then incorrectly processed and reinjected into the model's input IDs, leading to a GPU `device-side assert` and a subsequent crash of the vLLM worker. The issue is reproducible and can be triggered via the public gRPC request surface using an overlapping `Generate` / `Abort` sequence. In shared deployment environments, this vulnerability enables a service-wide DoS, impacting all clients and preventing further requests until the engine is manually restarted. The vulnerability has been confirmed on vLLM version 0.17.1, specifically when using models like `Qwen/Qwen3-0.6B-GPTQ-Int8`.

## Attack Chain

1. An attacker initiates a frontend-legal multi-request speculative workload on a vulnerable vLLM engine, maintaining structured-output state, speculative decoding, overlap, and request cancellation.
2. During the rejection sampling phase of speculative decoding, vLLM produces a recovered token that is equal to the model's `vocab_size` boundary value (e.g., 151936 for Qwen3).
3. This out-of-vocabulary token appears at position 0 of the sampled speculative row for a live request, with other positions potentially filled with padding.
4. In the next-token preparation step, vLLM erroneously treats this out-of-vocabulary token as a real next token for the request and converts its value to `-1`.
5. The drafter component then writes this converted `-1` back into the live next-step input-id row for the processing request.
6. The drafting, embedding, or attention path within the GPU worker attempts to consume this invalid `-1` token, leading to a `CUDA error: device-side assert triggered`.
7. The GPU worker crashes, causing the entire vLLM engine to fail and become unresponsive to further requests, resulting in a service-wide denial of service.

## Impact

A successful exploitation of CVE-2026-54234 allows any remote client capable of sending gRPC generation requests to crash the shared vLLM engine worker. This not only aborts all concurrent requests but also prevents any subsequent requests from completing until the worker is manually restarted. In deployments where vLLM is shared across multiple clients, this vulnerability can lead to a service-wide denial of service, affecting all users and applications relying on the vLLM instance. The issue is reliably reproducible, meaning attackers can sustain an outage through repeated requests.

## Recommendation

* Upgrade vLLM instances immediately to a version greater than or equal to 0.24.0 to remediate CVE-2026-54234, as described in the vLLM pull request linked in the references.
* Deploy the Sigma rule "Detect vLLM Engine DoS via Invalid Token Reinjection (CVE-2026-54234)" to your SIEM solution to detect server-side crash indicators.
* Monitor `logfile` sources on vLLM host systems for "CUDA error: device-side assert triggered" and "EngineCore encountered an issue" messages, as these are indicators of CVE-2026-54234 exploitation or other critical engine failures.
