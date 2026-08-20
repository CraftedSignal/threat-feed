---
title: Unauthenticated CPU Exhaustion DoS in netty-incubator-codec-bhttp
slug: 2026-08-netty-bhttp-dos
description: An infinite loop vulnerability in the BinaryHttpParser of netty-incubator-codec-bhttp allows unauthenticated attackers to exhaust event-loop threads and induce a persistent denial of service via specially crafted BHTTP requests.
date: "2026-08-20T19:12:42Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - netty
vendors:
  - Netty
products:
  - netty-incubator-codec-bhttp
  - netty-incubator-codec-ohttp
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A single ~17-byte Binary HTTP message pins one Netty event-loop thread at 100% CPU permanently.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-4899-mpch-38p3
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63202
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch all instances of netty-incubator-codec-bhttp to the corrected version identified in the vendor advisory.
      owner: IT Operations
      due: 24h
      evidence: Source advisory recommends immediate update and code-level fixes.
  mitigation_plan:
    - priority: immediate
      action: Monitor for sustained 100% CPU utilization on Netty event-loop threads as an indicator of attempted or successful exploitation.
      owner: SOC
      addresses: CVE-2026-63202
      evidence: Source documents CPU-bound spin as the primary impact of the exploit.
---

The `netty-incubator-codec-bhttp` library, used for decoding Binary HTTP (RFC 9292) messages, contains a critical control-flow defect in the `BinaryHttpParser.readFieldSection` method. The vulnerability arises from an improper loop termination condition (`fieldSectionLength != 0`) and the failure to enforce forward progress when processing field lines. 

An unauthenticated attacker can supply a malformed BHTTP request where the declared field-section length does not match the actual data. If the parser consumes zero bytes or consumes more bytes than declared, the loop enters an infinite busy-spin. Because the code relies on Java `assert` statements - which are stripped in production JVM environments - to guarantee termination and progress, the defect is fully exposed to remote exploitation. A small number of these requests can pin every available Netty event-loop thread at 100% CPU, resulting in a complete denial of service for OHTTP gateways or clients until the process is restarted.

## Attack Chain

1. Attacker obtains the target OHTTP gateway's public HPKE key configuration.
2. Attacker crafts a malicious BHTTP message where the declared field-section length is understated relative to the actual field line contents.
3. Attacker wraps the malicious BHTTP payload within a standard OHTTP request, encrypted with the gateway's public key.
4. OHTTP gateway receives the request and decrypts the chunk into the `binaryHttpCumulation` buffer.
5. `OHttpRequestResponseContext` passes the attacker-controlled plaintext directly to `BinaryHttpParser.parse`.
6. `BinaryHttpParser` enters the `readFieldSection` method and triggers the vulnerable `while` loop (lines 619-626).
7. The loop fails to terminate due to the `!= 0` condition or zero-byte progress, initiating an infinite CPU-bound spin.
8. Repeating the request exhausts the Netty event-loop group, leading to a total denial of service.

## Impact

The attack results in an unauthenticated, persistent denial of service. By pinning the event-loop threads of an OHTTP gateway or client, the attacker renders the service incapable of accepting new connections or processing traffic. The impact is significant for high-availability infrastructure relying on Netty-based OHTTP gateways, as the service remains unavailable until manual intervention (process restart) occurs.

## Recommendation

* Update `netty-incubator-codec-bhttp` to a version containing the patched `BinaryHttpParser` logic that replaces the vulnerable `while` loop with explicit exception handling.
* Promote input validation invariants previously handled by `assert` (lines 622, 624) to explicit `CorruptedFrameException` checks to ensure security regardless of JVM assertion settings.
* Verify that production deployments are not bypassing framing errors; ensure the parser enforces strict adherence to RFC 9292 regarding declared versus actual field-section length consumption.
