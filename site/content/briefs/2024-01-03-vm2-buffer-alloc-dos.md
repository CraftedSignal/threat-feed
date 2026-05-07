---
title: vm2 Sandbox Escape via Buffer.alloc Memory Exhaustion
slug: 2024-01-03-vm2-buffer-alloc-dos
description: A vulnerability exists in the vm2 npm package (<= 3.10.5) where sandboxed code can bypass the timeout protection by calling Buffer.alloc() with an arbitrary size, leading to memory exhaustion on the host system.
date: "2026-05-07T04:26:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sandbox-escape
  - dos
  - memory-exhaustion
  - vm2
vendors:
  - npm
products:
  - vm2 (<= 3.10.5)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Internal Defacement
references:
  - https://github.com/advisories/GHSA-6785-pvv7-mvg7
rules:
  - title: Detect Large Buffer.alloc Calls in vm2 Sandboxes
    description: Detects calls to Buffer.alloc with unusually large sizes within vm2 sandboxes, potentially indicating a memory exhaustion attack.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - process_creation
      - linux
  - title: Detect Node.js Process Crash Due to Heap Limit
    description: Detects Node.js process crashes due to reaching the heap limit, potentially caused by uncontrolled memory allocation.
    platform: sigma
    severity: critical
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - file_event
      - linux
  - title: Detect HTTP Requests Triggering Buffer.alloc
    description: Detects HTTP requests containing code that calls Buffer.alloc, potentially indicating an attempt to exploit memory allocation vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - webserver
      - linux
rules_count: 3
---

The vm2 npm package, a sandbox environment for executing untrusted JavaScript code, is susceptible to a denial-of-service attack.  Specifically, versions 3.10.5 and earlier allow sandboxed code to bypass the configured timeout by calling `Buffer.alloc()` with a large, attacker-controlled size. Because `Buffer.alloc` is a synchronous C++ native call, vm2's `timeout` option cannot interrupt it.  This bypass enables a malicious actor to exhaust the host system's memory, leading to a crash. This is particularly impactful in memory-constrained environments like Docker containers, Kubernetes pods, and serverless functions (e.g., AWS Lambda), where a single request can trigger an out-of-memory (OOM) error, resulting in service disruption. The amplification factor can be significant, with a small HTTP request (e.g., 100 bytes) triggering a large memory allocation (e.g., 100MB+).

## Attack Chain

1. An attacker sends a malicious HTTP request to an application using vm2.
2. The request contains JavaScript code intended for execution within the vm2 sandbox via an API endpoint (e.g. `/api/execute`).
3. The malicious JavaScript code leverages `Buffer.alloc()` with a large size (e.g., `Buffer.alloc(1024*1024*100)`).
4. The `Buffer.alloc()` call is proxied to the host environment through the bridge proxy in `lib/bridge.js` without size validation.
5. The host system attempts to allocate the requested memory synchronously.
6. In memory-constrained environments, the allocation exceeds available resources.
7. The Node.js process crashes with a `FATAL ERROR: Reached heap limit` due to JavaScript heap exhaustion.
8. The application becomes unavailable, resulting in a denial-of-service condition.

## Impact

This vulnerability allows for denial-of-service (DoS) attacks. A single HTTP request containing malicious JavaScript code can crash the host Node.js process by exhausting its memory. The severity of the impact depends on the environment.  In memory-constrained environments such as Docker containers or Kubernetes pods, the attack causes immediate process termination. Even in unconstrained environments where the memory allocation might succeed and be reclaimed, the attack can cause temporary performance degradation. The vulnerability affects all applications using vm2 version 3.10.5 or earlier in its default configuration.

## Recommendation

*   Upgrade to a patched version of the `vm2` package that addresses this vulnerability.
*   Apply rate limiting to the API endpoints that execute code within the vm2 sandbox to mitigate the impact of potential attacks.
*   Monitor application logs for `FATAL ERROR: Reached heap limit` messages, which may indicate exploitation attempts.
*   Deploy the Sigma rule to detect suspicious calls to Buffer.alloc with unusually large sizes.
*   Implement resource limits (e.g., memory limits) for processes running vm2 to prevent complete system exhaustion.
