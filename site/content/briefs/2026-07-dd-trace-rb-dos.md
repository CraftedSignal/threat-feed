---
title: 'dd-trace-rb: Improper Parsing of W3C Baggage Headers Leads to DoS'
slug: 2026-07-dd-trace-rb-dos
description: A vulnerability (CVE-2026-50276) in Datadog tracing libraries, specifically `dd-trace-rb` versions prior to 2.32.0, allows a remote and unauthenticated attacker to perform a Denial of Service (DoS) by sending HTTP requests with malformed W3C baggage headers, leading to unbounded CPU and memory consumption.
date: "2026-07-15T23:09:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - ruby
  - web
vendors:
  - Datadog
products:
  - dd-trace-rb < 2.32.0
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: The tracer allocates a hash-map entry for each pair on every request, causing unbounded CPU and memory consumption and enabling a remote Denial of Service against any HTTP service that has the baggage propagation style enabled.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-p5f6-rccc-jv98
  - https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-mh2q-q3fh-2475
  - https://github.com/open-telemetry/opentelemetry-dotnet/security/advisories/GHSA-g94r-2vxg-569j
---

A high-severity vulnerability (CVE-2026-50276) in Datadog tracing libraries, specifically `dd-trace-rb` versions prior to 2.32.0, allows a remote and unauthenticated attacker to execute a Denial of Service (DoS) attack. The flaw stems from improper parsing of incoming W3C baggage HTTP headers; while limits exist for baggage injection, the library fails to enforce item-count or byte-size limits during extraction. This means an attacker can send a request containing a `baggage` header with an arbitrarily large number of comma-separated key-value pairs or a single very large value. The tracer's attempt to allocate a hash-map entry for each pair on every request leads to unbounded CPU and memory consumption. This vulnerability affects any internet-facing HTTP service instrumented with an affected `dd-trace-rb` version, particularly as baggage propagation style is often enabled by default, making them susceptible to remote resource exhaustion and service unavailability.

## Attack Chain

1. An attacker identifies an internet-facing HTTP service instrumented with a vulnerable `dd-trace-rb` library.
2. The attacker crafts an HTTP request containing an excessively long or item-rich `W3C baggage` header.
3. The crafted HTTP request is sent to the target service.
4. The vulnerable `dd-trace-rb` library within the service receives the request and attempts to parse the `baggage` header.
5. The library allocates hash-map entries for each key-value pair or attempts to process the single large value without enforcing item-count or byte-size limits during the extraction process.
6. This uncontrolled parsing and allocation causes unbounded CPU and memory consumption within the application process.
7. The application becomes unresponsive or crashes due to resource exhaustion, resulting in a Denial of Service for legitimate users.

## Impact

The vulnerability allows a remote, unauthenticated attacker to cause a Denial of Service (DoS) against any HTTP service instrumented with affected `dd-trace-rb` versions. The impact manifests as unbounded CPU and memory consumption, leading to application unresponsiveness, crashes, and complete service unavailability. This is particularly critical as baggage propagation style is enabled by default in most affected tracers, exposing a wide range of internet-facing services unless explicit mitigation steps have been taken. The vulnerability can disrupt critical services and business operations by rendering applications inaccessible.

## Recommendation

* Upgrade `dd-trace-rb` to version 2.32.0 or later to patch CVE-2026-50276.
* Disable `baggage` extraction by removing `baggage` from the `DD_TRACE_PROPAGATION_STYLE` or `DD_TRACE_PROPAGATION_STYLE_EXTRACT` environment variables if immediate upgrade is not possible.
* Implement HTTP request header size limits at upstream proxies or web servers, such as Apache's `LimitRequestFieldSize`, Nginx's `large_client_header_buffers`, or Envoy's `max_request_headers_kb`, to prevent oversized headers from reaching the application.
