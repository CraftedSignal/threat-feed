---
title: Hoverfly Process Crash via Concurrent Map Write Race Condition
slug: 2026-07-hoverfly-dos
description: Hoverfly, when running in Diff mode, is vulnerable to a denial-of-service condition due to a concurrent map write race condition in the `AddDiff()` function. Multiple proxy requests processed simultaneously cause unsynchronized writes to the shared `responsesDiff` map, triggering Go's built-in race detector and a `fatal error`, which immediately terminates the Hoverfly process. This vulnerability is trivially exploitable by sending multiple concurrent requests to the proxy port, leading to a full denial of service that cannot be recovered without a restart.
date: "2026-07-14T19:22:14Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - race-condition
  - denial-of-service
  - go-lang
vendors:
  - SpectoLabs
products:
  - Hoverfly (<= 1.12.7)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: The process terminates immediately and cannot be recovered without a restart... the entire Hoverfly process.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-qrh4-p6v4-mrfg
---

Hoverfly, a lightweight service virtualization tool, is affected by CVE-2026-50013, a high-severity denial-of-service vulnerability. This flaw exists specifically when Hoverfly is operating in its "Diff mode." The vulnerability stems from an unsynchronized write operation to the internal `responsesDiff` map within the `AddDiff()` function. When multiple HTTP proxy requests are handled concurrently - a common scenario for any proxy - multiple goroutines attempt to modify this shared map simultaneously without proper locking mechanisms (such as a mutex). Go's runtime environment, designed to detect such concurrent map accesses, triggers a `fatal error: concurrent map read and map write`. This unrecoverable error immediately terminates the entire Hoverfly process. The vulnerability is trivial to exploit; any attacker with network access to the Hoverfly proxy port can initiate a denial-of-service simply by sending multiple simultaneous requests, causing the application to crash. Affected versions include Hoverfly v1.12.7 and earlier, impacting any organization utilizing Diff mode for API comparison or testing.

## Attack Chain

1. An attacker gains network access to a running Hoverfly proxy instance.
2. The Hoverfly instance is explicitly configured to operate in "Diff mode."
3. The attacker sends multiple, concurrent HTTP proxy requests through the Hoverfly instance, targeting any upstream URL.
4. Each concurrent request processed by Hoverfly triggers a separate goroutine to invoke the `AddDiff()` function.
5. Inside `AddDiff()`, these multiple goroutines attempt to perform unsynchronized read and write operations on the shared `responsesDiff` map.
6. Go's runtime environment detects the concurrent map read and write conflict, identifying a critical race condition.
7. The Go runtime explicitly executes a `fatal error: concurrent map read and map write` due to its built-in race detection mechanism.
8. The entire Hoverfly process immediately terminates, resulting in a complete denial of service for all users.

## Impact

This vulnerability leads to a full denial of service (DoS) for any Hoverfly instance running in Diff mode. The process terminates immediately upon exploitation and cannot be recovered without a manual restart. The exploitation is trivial, requiring only network access to the proxy port and no specific administrative API access. Because Go's `fatal error` mechanism is unrecoverable, the process is unconditionally killed, preventing any programmatic recovery attempts. This affects any team or environment using Hoverfly in Diff mode for tasks such as API comparison or testing, potentially disrupting development pipelines, QA environments, or any other service relying on the proxy. The vulnerability impacts Hoverfly versions up to and including v1.12.7.

## Recommendation

* Patch CVE-2026-50013 by upgrading Hoverfly to a version that addresses this vulnerability once available.
* Until a patch for CVE-2026-50013 is applied, avoid running Hoverfly in "Diff mode" in production or externally exposed environments.
* Implement network segmentation and firewall rules to restrict access to the Hoverfly proxy port, allowing only trusted IP ranges to connect.
