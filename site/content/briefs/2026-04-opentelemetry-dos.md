---
title: OpenTelemetry-Go Multi-Value Baggage Header DOS Vulnerability
slug: 2026-04-opentelemetry-dos
description: A vulnerability in OpenTelemetry-Go allows attackers to amplify CPU and allocation usage by sending many `baggage:` header lines, leading to a denial-of-service condition due to excessive resource consumption.
date: "2026-04-08T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - dos
  - opentelemetry
  - header injection
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Standard Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.001
    technique_name: 'Endpoint Denial of Service: Application Exhaustion'
references:
  - https://github.com/advisories/GHSA-mh2q-q3fh-2475
  - https://github.com/open-telemetry/opentelemetry-go/blob/1ee4a4126dbdd1bc79e9fae072fa488beffac52a/propagation/baggage.go#L58
rules:
  - title: Detect High Baggage Header Count
    description: Detects HTTP requests with a large number of baggage headers, potentially indicating a denial-of-service attempt.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect Large Allocations from Baggage Parsing
    description: Detects processes that may be allocating excessive memory due to baggage parsing in OpenTelemetry.
    platform: sigma
    severity: low
    tactics:
      - denial_of_service
      - resource_hijacking
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A remote denial-of-service vulnerability exists in OpenTelemetry-Go versions 1.36.0 through 1.40.0. The vulnerability stems from the `extractMultiBaggage` function parsing each `baggage:` header field-value independently and aggregating members across values. This allows an attacker to bypass the intended 8192-byte per-value parse limit by sending numerous `baggage:` header lines. Even when individual header values are within the limit, the aggregate parsing overhead can exhaust server resources. Exploitation involves crafting malicious HTTP requests containing a high number of `baggage` headers. This vulnerability poses a risk to services utilizing affected OpenTelemetry-Go versions by allowing attackers to trigger excessive CPU and memory allocation, resulting in increased latency or service unavailability. The issue was identified and reported in the OpenTelemetry-Go project, leading to the reported advisory.

## Attack Chain

1. The attacker crafts an HTTP request targeting a server running an application instrumented with the vulnerable OpenTelemetry-Go library (versions 1.36.0-1.40.0).
2. The attacker includes multiple `baggage:` headers in the HTTP request. Each `baggage:` header contains a value that is individually within the 8192-byte limit.
3. The HTTP request is received by the server and processed by the `net/http` handler.
4. The `propagation.HeaderCarrier.Values("baggage")` function extracts all `baggage` header values from the request.
5. For each `baggage` header value, the `extractMultiBaggage` function calls `baggage.Parse`, leading to independent parsing and member aggregation.
6. Due to the large number of `baggage` headers, the repeated parsing and member aggregation consumes excessive CPU and memory resources.
7. The server experiences increased latency or becomes unresponsive due to resource exhaustion.
8. The application becomes unavailable, leading to a denial-of-service condition.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition, impacting the availability of applications using the affected OpenTelemetry-Go library versions (1.36.0 to 1.40.0). In a default `net/http` configuration (max header bytes 1MB), a single request with many `baggage:` header field-values can cause large per-request allocations and increased latency. The provided proof of concept demonstrates a significant increase in per-request allocation bytes (from 133,429 to 10,315,458) and p95 latency (from 0ms to 7ms) when using multiple `baggage` headers. This can severely degrade performance and potentially render the service unavailable to legitimate users.

## Recommendation

*   Upgrade to a patched version of the `go.opentelemetry.io/otel/baggage` and `go.opentelemetry.io/otel/propagation` modules that addresses CVE-2026-29181.
*   Implement a mitigation strategy to limit the number of `baggage` headers processed per request.
*   Deploy the Sigma rule "Detect High Baggage Header Count" to identify requests with an excessive number of baggage headers.
*   Monitor web server logs for requests with a high number of `baggage` headers and investigate potential abuse.
