---
title: Datadog dd-trace-js W3C Baggage Header Denial of Service Vulnerability
slug: 2026-07-dd-trace-js-dos
description: The Datadog `dd-trace-js` library, specifically versions older than 5.100.0, is vulnerable to a Denial of Service (DoS) attack where improper parsing of W3C baggage HTTP headers allows a remote, unauthenticated attacker to send requests with an arbitrarily large number of comma-separated key-value pairs, leading to unbounded CPU and memory consumption and enabling a remote DoS against any HTTP service instrumented with the affected library where baggage propagation is enabled.
date: "2026-07-15T22:59:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - javascript
  - nodejs
  - datadog
vendors:
  - Datadog
products:
  - dd-trace-js (< 5.100.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: The tracer allocates a hash-map entry for each pair on every request, causing unbounded CPU and memory consumption and enabling a remote Denial of Service against any HTTP service
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-wxqq-gcq8-c443
  - https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-mh2q-q3fh-2475
  - https://github.com/open-telemetry/opentelemetry-dotnet/security/advisories/GHSA-g94r-2vxg-569j
---

A high-severity Denial of Service (DoS) vulnerability, tracked as CVE-2026-50272, affects Datadog's `dd-trace-js` library in versions prior to 5.100.0. This flaw stems from the library's improper parsing of W3C baggage HTTP headers. While limits (`DD_TRACE_BAGGAGE_MAX_ITEMS` and `DD_TRACE_BAGGAGE_MAX_BYTES`) are enforced during baggage injection, they are not applied during extraction. This allows a remote, unauthenticated attacker to craft and send HTTP requests containing an arbitrarily large number of comma-separated key-value pairs or a single very large value within the `baggage` header. When a vulnerable service receives such a request, the `dd-trace-js` tracer attempts to allocate a hash-map entry for each pair, leading to unbounded consumption of CPU and memory resources, ultimately resulting in a Denial of Service. The baggage propagation style, which enables this vulnerability, is often enabled by default in affected tracers, making internet-facing services instrumented with these versions particularly susceptible.

## Attack Chain

1. **Attacker crafts malicious HTTP request**: A remote, unauthenticated attacker constructs an HTTP request targeting an internet-facing service instrumented with `dd-trace-js`.
2. **Injects oversized W3C baggage header**: The attacker inserts a W3C `baggage` HTTP header into the request, containing an exceptionally large number of comma-separated key-value pairs or a single, extremely long value.
3. **Request sent to vulnerable service**: The malicious HTTP request is transmitted to the target service.
4. **Vulnerable `dd-trace-js` receives request**: The service, running a vulnerable version of `dd-trace-js` (prior to 5.100.0) with baggage propagation enabled by default, receives the request.
5. **Improper header parsing occurs**: The `dd-trace-js` library attempts to extract the baggage items from the oversized header without enforcing any item-count or byte-size limits on the extraction path.
6. **Resource exhaustion**: The library continuously allocates hash-map entries for each perceived key-value pair, leading to unbounded consumption of CPU and memory resources.
7. **Denial of Service**: The target service becomes unresponsive or crashes due to resource exhaustion, resulting in a Denial of Service for legitimate users.

## Impact

Successful exploitation of CVE-2026-50272 leads to a Denial of Service (DoS) against HTTP services that are instrumented with vulnerable versions of the `dd-trace-js` library (prior to 5.100.0). Attackers can trigger this by sending a crafted HTTP request with an oversized W3C baggage header, causing the tracer to consume unbounded CPU and memory resources. This resource exhaustion can crash the targeted service, making it unavailable to legitimate users. Any internet-facing service utilizing the affected library with the baggage propagation style enabled (which is often the default configuration) is at risk, potentially leading to significant service disruption and operational downtime.

## Recommendation

* Upgrade the `dd-trace-js` library to version `5.100.0` or later immediately to patch CVE-2026-50272.
* If immediate upgrade is not feasible, disable `baggage` extraction by modifying `DD_TRACE_PROPAGATION_STYLE` or `DD_TRACE_PROPAGATION_STYLE_EXTRACT` to remove `baggage`.
* Implement upstream proxy or web server configurations to cap the maximum HTTP request header size. For example, configure Apache `LimitRequestFieldSize`, Nginx `large_client_header_buffers`, or Envoy `max_request_headers_kb`.
