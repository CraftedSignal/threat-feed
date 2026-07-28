---
title: td Library Denial of Service via Unbounded Memory Allocation
slug: 2026-07-td-dos-unbounded-memory
description: A denial-of-service vulnerability exists in the `go/github.com/gotd/td` library versions prior to 0.145.1. A remote, unauthenticated attacker can exploit this by sending a crafted unencrypted MTProto packet during the handshake. This packet declares a large `dataLen` value, forcing the application to allocate an excessive amount of memory, potentially leading to out-of-memory (OOM) termination and denial of service due to unbounded memory allocation before length validation.
date: "2026-07-28T22:17:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - denial-of-service
  - vulnerability
  - go-lang
vendors:
  - gotd
products:
  - go/github.com/gotd/td (< 0.145.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: A remote, unauthenticated attacker can cause excessive memory allocation (and resulting CPU / GC pressure, potentially OOM termination) by sending a crafted unencrypted MTProto packet.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-whmm-qj9r-wvr2
---

A high-severity denial-of-service vulnerability, tracked as CVE-2026-54638, affects the `go/github.com/gotd/td` library versions prior to 0.145.1. This flaw stems from an unbounded memory allocation in the `(*proto.UnencryptedMessage).Decode` function. A remote, unauthenticated attacker can exploit this by sending a specially crafted unencrypted MTProto packet during the initial handshake phase. The packet includes a manipulated 32-bit `dataLen` field that declares a multi-gigabyte payload. Critically, the vulnerable function attempts to allocate a buffer of the declared size *before* validating that the actual incoming data stream contains the specified number of bytes. This premature allocation of excessive memory can lead to significant CPU and garbage collection pressure, and ultimately, Out-Of-Memory (OOM) termination, rendering the affected application unavailable. There is no evidence of memory corruption or code execution associated with this vulnerability.

## Attack Chain

1. A remote, unauthenticated attacker initiates communication with a service using the `go/github.com/gotd/td` library, targeting the MTProto handshake path.
2. The attacker crafts an unencrypted MTProto packet containing a manipulated 32-bit `dataLen` field, declaring an arbitrarily large payload size (e.g., `0x70000000`, approximately 1.75 GB).
3. The crafted packet is sent to the vulnerable application.
4. The `(*proto.UnencryptedMessage).Decode` function receives the packet.
5. Before validating if the incoming buffer actually contains the declared `dataLen` number of bytes, the function attempts to allocate a buffer of that size using `make([]byte, dataLen)`.
6. This forced allocation of a multi-gigabyte buffer consumes an excessive amount of system memory.
7. The application experiences high CPU and garbage collection (GC) pressure due to the memory allocation attempt.
8. The system runs out of memory, causing the application to crash or terminate (Out-Of-Memory), resulting in a denial-of-service condition.

## Impact

The primary impact of CVE-2026-54638 is a denial-of-service against applications using the vulnerable `go/github.com/gotd/td` library. Successful exploitation by a remote, unauthenticated attacker will cause excessive memory allocation, leading to significant CPU and garbage collection overhead, and potentially an Out-Of-Memory (OOM) termination of the application. This renders the service unavailable to legitimate users. The vulnerability specifically targets system availability and does not lead to memory corruption, out-of-bounds access, or remote code execution.

## Recommendation

* Upgrade the `go/github.com/gotd/td` library to version 0.145.1 or later to patch CVE-2026-54638.
* Ensure that all applications using the `go/github.com/gotd/td` package are updated to a non-vulnerable version to mitigate the risk of denial-of-service attacks.
