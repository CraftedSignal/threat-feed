---
title: 'CVE-2026-59892: OpenTelemetry JaegerPropagator Denial of Service'
slug: 2026-07-opentelemetry-jaeger-dos
description: A critical denial of service vulnerability, CVE-2026-59892, exists in `@opentelemetry/propagator-jaeger` versions prior to 2.9.0, allowing an unauthenticated remote attacker to terminate Node.js applications configured with `JaegerPropagator` by sending a malformed percent-encoded value in `uber-trace-id` or `uberctx-*` HTTP headers, leading to an uncaught `URIError`.
date: "2026-07-21T19:12:07Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - denial-of-service
  - vulnerability
  - javascript
  - nodejs
  - opentelemetry
vendors:
  - OpenTelemetry
products:
  - '@opentelemetry/propagator-jaeger (< 2.9.0)'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Server Denial of Service
    evidence: terminating any Node.js process that uses `JaegerPropagator` as its active propagator
    confidence_band: high
cves:
  - id: CVE-2026-59892
    cvss: 7.5
    epss: 0.00436
references:
  - https://github.com/advisories/GHSA-45rx-2jwx-cxfr
---

An unauthenticated remote denial-of-service vulnerability (CVE-2026-59892) affects Node.js applications utilizing `@opentelemetry/propagator-jaeger` versions older than 2.9.0. This flaw allows an attacker to send a specially crafted HTTP request containing a malformed percent-encoded value (such as a bare '%') within the `uber-trace-id` or `uberctx-*` HTTP headers. When `JaegerPropagator` attempts to decode this malformed header value using `decodeURIComponent()`, an uncaught `URIError` is triggered. If `JaegerPropagator` is configured as the sole active propagator, this exception propagates as an `uncaughtException`, causing the entire Node.js process to terminate immediately. This vulnerability allows for easy service disruption with a single request.

## Attack Chain

1. An unauthenticated attacker sends an HTTP request to a target Node.js service.
2. The HTTP request includes a header, such as `uber-trace-id` or `uberctx-*`, with a malformed percent-encoded value (e.g., `uber-trace-id: %` or `uberctx-user: %`).
3. The target service is running a Node.js application that uses `@opentelemetry/propagator-jaeger` version < 2.9.0.
4. The application has `JaegerPropagator` registered as its active global propagator (e.g., via `OTEL_PROPAGATORS=jaeger` or `propagation.setGlobalPropagator(new JaegerPropagator())`).
5. During context extraction, the `JaegerPropagator.extract()` method attempts to decode the malformed header value using `decodeURIComponent()`.
6. The `decodeURIComponent()` function throws a `URIError: URI malformed` due to the invalid percent-encoding.
7. Since the `JaegerPropagator` is not wrapped by a `CompositePropagator` (which would catch the error), the `URIError` propagates as an `uncaughtException`.
8. The Node.js process immediately terminates, resulting in a denial of service for the application.

## Impact

This vulnerability leads to a severe denial of service, allowing any unauthenticated remote attacker to terminate vulnerable Node.js applications with a single HTTP request. This disrupts service availability and can lead to significant downtime for affected organizations. The impact is specifically on service availability; confidentiality and integrity of data are not directly affected by this particular flaw. Organizations in any sector using the affected OpenTelemetry library configurations are susceptible to this easy-to-exploit DoS vector.

## Recommendation

* Upgrade `@opentelemetry/propagator-jaeger` to version 2.9.0 or later to patch CVE-2026-59892.
* As an interim mitigation, if immediate upgrading is not possible, implement controls at your edge (e.g., reverse proxy, API gateway, or load balancer like Nginx or Envoy) to strip or validate `uber-trace-id` and `uberctx-*` headers on all inbound requests. Ensure these headers are only accepted from trusted upstream services.
* Verify if your `OTEL_PROPAGATORS` environment variable is set to include `jaeger` or if `propagation.setGlobalPropagator(new JaegerPropagator())` is called in your code.
