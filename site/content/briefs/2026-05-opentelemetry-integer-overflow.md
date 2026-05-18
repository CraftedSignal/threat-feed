---
title: OpenTelemetry eBPF Instrumentation (OBI) Memcached Integer Overflow DoS
slug: 2026-05-opentelemetry-integer-overflow
description: A remotely reachable integer overflow in OpenTelemetry eBPF Instrumentation's (OBI) memcached text protocol parser can crash the OBI process, causing a denial of service due to unchecked arithmetic when handling large payload sizes in memcached storage commands.
date: "2026-05-18T20:22:53Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - integer-overflow
  - memcached
  - opentelemetry
vendors:
  - opentelemetry
products:
  - go.opentelemetry.io/obi
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.003
    technique_name: 'Application Layer Protocol: Memcached'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-43g7-cwr8-q3jh
  - CVE-2026-45686
rules:
  - title: Detect OpenTelemetry OBI Memcached Integer Overflow Attempt
    description: Detects attempts to exploit the OpenTelemetry OBI memcached integer overflow vulnerability (CVE-2026-45686) by identifying memcached storage commands with abnormally large byte sizes.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499
    data_sources:
      - network_connection
      - zeek
rules_count: 1
---

A denial-of-service vulnerability exists in the memcached text protocol parser within OpenTelemetry eBPF Instrumentation (OBI). The vulnerability resides in the `pkg/ebpf/common/memcached_detect_transform.go` file, where the parser lacks proper bounds checking when handling the `<bytes>` field of memcached storage commands (`set`, `add`, `replace`, `append`, `prepend`, `cas`). By sending a crafted memcached request with an extremely large `<bytes>` value (e.g., `math.MaxInt` or `math.MaxInt-1`), an attacker can cause an integer overflow during payload length calculation. This overflow results in a negative payload length being passed to `LargeBufferReader.Peek` in `pkg/internal/largebuf/large_buffer.go`, triggering a runtime panic and crashing the OBI process. This vulnerability affects OBI versions 0.7.0 to 0.8.x, allowing a remote attacker to disrupt telemetry collection.

## Attack Chain

1. Attacker identifies an OBI instance instrumenting memcached traffic.
2. Attacker crafts a memcached storage command (e.g., `set`) with a large `<bytes>` field (close to `math.MaxInt`).
3. Attacker sends the crafted memcached storage command to a service instrumented by the vulnerable OBI instance on port 11211.
4. OBI's memcached request parser (`memcachedCommandBytesField` in `pkg/ebpf/common/memcached_detect_transform.go`) receives the crafted command and parses the `<bytes>` field using `strconv.Atoi`.
5. OBI calculates the payload length by adding the `<bytes>` value to the length of the trailing `\r\n` delimiter.
6. Due to the large `<bytes>` value, the addition overflows, resulting in a negative `payloadLen`.
7. The negative `payloadLen` is passed to `LargeBufferReader.Peek` in `pkg/internal/largebuf/large_buffer.go`.
8. `LargeBufferReader.Peek` attempts to slice a buffer with the negative length, causing a Go runtime panic and crashing the OBI process.

## Impact

Successful exploitation of this vulnerability results in a denial of service (DoS) against the OBI process. This leads to a loss of telemetry data collection for any services being monitored by the affected OBI instance. The attacker only needs to send a crafted memcached storage command to a service that OBI is instrumenting. This vulnerability impacts OBI deployments where the memcached parser is active and the instrumented services are reachable or influenceable by an attacker.

## Recommendation

*   Deploy the Sigma rule `Detect OpenTelemetry OBI Memcached Integer Overflow Attempt` to detect crafted memcached storage commands with extremely large `<bytes>` values in network traffic.
*   Monitor OBI process logs and container status for crashes originating from `LargeBufferReader.Peek`, as indicated in the overview, to identify potential exploitation attempts.
*   Consider filtering or sanitizing memcached storage command inputs to prevent excessively large `<bytes>` values from reaching instrumented services.
