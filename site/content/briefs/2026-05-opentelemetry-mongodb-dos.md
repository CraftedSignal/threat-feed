---
title: OpenTelemetry eBPF Instrumentation MongoDB Parser Denial-of-Service
slug: 2026-05-opentelemetry-mongodb-dos
description: Malformed MongoDB wire messages can trigger uncaught panics in the OpenTelemetry eBPF Instrumentation agent's MongoDB TCP parser, allowing a remote unauthenticated attacker to crash the telemetry agent and cause a denial of service.
date: "2026-05-18T20:20:25Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - opentelemetry
  - mongodb
  - denial-of-service
  - CVE-2026-45685
vendors:
  - OpenTelemetry
products:
  - go.opentelemetry.io/obi
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-j8p6-96vp-f3r9
rules:
  - title: Detect OpenTelemetry MongoDB Parser Denial-of-Service Attempt
    description: Detects attempts to crash the OpenTelemetry eBPF Instrumentation agent by sending malformed MongoDB OP_MSG packets.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-45685
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - linux
  - title: Detect OpenTelemetry MongoDB Parser BSON Type Assertion Panic Attempt
    description: Detects potential attempts to trigger a BSON type assertion panic in the OpenTelemetry agent via crafted MongoDB traffic
    platform: sigma
    severity: medium
    tactics:
      - cve-2026-45685
      - denial_of_service
    techniques:
      - T1499.004
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

The OpenTelemetry eBPF Instrumentation agent is susceptible to a denial-of-service vulnerability in its MongoDB protocol parser. This vulnerability, present in versions v0.1.0 through v0.8.0 of `go.opentelemetry.io/obi`, allows a remote, unauthenticated attacker to crash the telemetry agent by sending specially crafted MongoDB wire messages. The parser operates on raw attacker-controlled network payloads before full validation, leading to uncaught panics and process termination. A single malformed packet can halt telemetry collection, impacting observability. Patches addressing these panics were introduced in versions v0.4.0 and later, but the BSON type-assertion issue persists through v0.8.0. This vulnerability, assigned CVE-2026-45685, can disrupt telemetry collection in deployments that monitor traffic from untrusted or partially trusted MongoDB clients. The affected code paths are in `pkg/ebpf/common/mongo_detect_transform.go`.

## Attack Chain

1. Attacker crafts a malformed MongoDB OP_MSG packet or BSON document.
2. Attacker sends the crafted packet to the monitored MongoDB instance.
3. The OpenTelemetry eBPF Instrumentation agent intercepts the MongoDB traffic.
4. The agent's `parseOpMessage` function attempts to read flag bits from the packet without proper bounds checking (versions v0.1.0-v0.3.0).
5. The agent's `parseSections` function attempts to read document-sequence length without proper bounds checking (versions v0.1.0-v0.3.0).
6. The agent's `parseFirstField` function performs an unchecked type assertion on BSON field values (versions v0.1.0-v0.8.0).
7. The MongoDB parser encounters a slice-bounds panic or type assertion panic.
8. The OpenTelemetry eBPF Instrumentation agent process terminates, leading to a denial of service and loss of telemetry data.

## Impact

Successful exploitation of this vulnerability results in a denial of service. An unauthenticated attacker can crash the OpenTelemetry eBPF Instrumentation agent by sending a crafted OP_MSG packet or malformed BSON document to a monitored MongoDB instance. This leads to a loss of observability until the agent process is restarted. This vulnerability impacts deployments that enable MongoDB parsing and process attacker-controlled or potentially malformed MongoDB traffic.

## Recommendation

*   Upgrade the `go.opentelemetry.io/obi` package to version 0.9.0 or later to address the vulnerability described in CVE-2026-45685.
*   Deploy the Sigma rule "Detect OpenTelemetry MongoDB Parser Denial-of-Service Attempt" to identify suspicious network traffic targeting MongoDB instances that could trigger this vulnerability.
*   Monitor network traffic for malformed MongoDB packets, specifically those with truncated OP_MSG packets or malformed BSON documents.
