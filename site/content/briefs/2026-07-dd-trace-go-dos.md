---
title: Datadog dd-trace-go Library Vulnerability May Lead to Denial of Service
slug: 2026-07-dd-trace-go-dos
description: A vulnerability, CVE-2026-50274, in Datadog's `dd-trace-go` library (versions <= 1.24.1 and v2 < 2.8.1) allows a remote, unauthenticated attacker to cause a Denial of Service (DoS) by sending HTTP requests with oversized W3C baggage headers, leading to unbounded CPU and memory consumption in instrumented services.
date: "2026-07-15T23:06:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - supply-chain
  - go
  - datadog
vendors:
  - Datadog
products:
  - go/github.com/DataDog/dd-trace-go (<= 1.24.1)
  - go/github.com/DataDog/dd-trace-go/v2 (< 2.8.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: A remote, unauthenticated attacker can send a request whose baggage header contains an arbitrarily large number of comma-separated key-value pairs (or a single very large value). The tracer allocates a hash-map entry for each pair on every request, causing unbounded CPU and memory consumption and enabling a remote Denial of Service against any HTTP service that has the baggage propagation style enabled.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-74j5-xf3v-crq8
  - https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-mh2q-q3fh-2475
  - https://github.com/open-telemetry/opentelemetry-dotnet/security/advisories/GHSA-g94r-2vxg-569j
---

A high-severity vulnerability, identified as CVE-2026-50274, exists in the Datadog `dd-trace-go` tracing libraries, specifically versions 1.x (up to 1.24.1) and 2.x (up to 2.8.0). This flaw stems from improper parsing of incoming W3C baggage HTTP headers, where the libraries fail to enforce item-count or byte-size limits during the extraction process. The default limits (DD_TRACE_BAGGAGE_MAX_ITEMS=64, DD_TRACE_BAGGAGE_MAX_BYTES=8192) are only applied during baggage injection, not extraction. This oversight allows a remote, unauthenticated attacker to send specially crafted HTTP requests containing an arbitrarily large number of comma-separated key-value pairs or a single very large value within the baggage header. This malicious input causes the tracer to allocate an excessive number of hash-map entries for each request, leading to unbounded CPU and memory consumption, ultimately resulting in a Denial of Service (DoS) against any HTTP service instrumented with the affected tracer version where baggage propagation is enabled by default.

## Attack Chain

1. An unauthenticated attacker crafts an HTTP request targeting an internet-facing service instrumented with a vulnerable `dd-trace-go` library.
2. The attacker includes a W3C `baggage` HTTP header in the request containing an exceptionally large number of comma-separated key-value pairs or a single, very large value.
3. The vulnerable `dd-trace-go` library, upon receiving the request, attempts to parse and extract the W3C baggage header.
4. Due to the lack of item-count or byte-size limits during extraction, the tracer allocates a hash-map entry for each key-value pair.
5. This unbounded allocation leads to significant and continuous increases in the service's CPU utilization and memory consumption.
6. The sustained resource exhaustion prevents the service from processing legitimate requests, resulting in a Denial of Service (DoS).

## Impact

Successful exploitation of CVE-2026-50274 leads to a Denial of Service (DoS) condition on affected HTTP services. Attackers can remotely trigger unbounded CPU and memory consumption, causing the service to become unresponsive or crash. This impacts the availability of critical applications that rely on the `dd-trace-go` library for distributed tracing, potentially disrupting business operations and hindering monitoring capabilities. The vulnerability affects services that have baggage propagation style enabled by default or explicitly configured.

## Recommendation

* Patch CVE-2026-50274 immediately by upgrading `dd-trace-go` to version 2.8.1 or later. For those using `dd-trace-go` 1.x, the recommendation is to migrate to `v2.8.1` or newer.
* If immediate upgrade to `dd-trace-go` version 2.8.1 is not feasible, disable `baggage` extraction by removing `baggage` from the `DD_TRACE_PROPAGATION_STYLE` environment variable. Alternatively, if `DD_TRACE_PROPAGATION_STYLE_EXTRACT` is set independently, remove `baggage` from its value.
* As an additional mitigation, cap the maximum HTTP request header size at an upstream proxy or web server. Refer to documentation for Apache (`LimitRequestFieldSize`), Nginx (`large_client_header_buffers`), or Envoy (`max_request_headers_kb`) to configure appropriate limits for HTTP header sizes.
