---
title: OpenTelemetry Prometheus Exporter Denial-of-Service via Malformed HTTP Request (CVE-2026-44902)
slug: 2026-05-opentelemetry-prometheus-dos
description: A malformed HTTP request can crash any Node.js process running the OpenTelemetry JS Prometheus exporter. The metrics endpoint has no error handling around URL parsing, so a request with an invalid URI causes an uncaught `TypeError` that terminates the process, leading to a denial of service. Update `@opentelemetry/exporter-prometheus` and `@opentelemetry/sdk-node` to version **0.217.0** or later and `@opentelemetry/auto-instrumentations-node` to version **0.75.0** or later to remediate.
date: "2026-05-11T14:43:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - otel
  - prometheus
  - CVE-2026-44902
vendors:
  - OpenTelemetry
products:
  - '@opentelemetry/exporter-prometheus'
  - '@opentelemetry/sdk-node'
  - '@opentelemetry/auto-instrumentations-node'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-q7rr-3cgh-j5r3
rules:
  - title: Detect OpenTelemetry Prometheus Exporter Malformed HTTP Request
    description: Detects CVE-2026-44902 exploitation — Malformed HTTP request targeting the OpenTelemetry Prometheus exporter.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
  - title: Detect OpenTelemetry Prometheus Exporter Invalid Host Header
    description: Detects CVE-2026-44902 exploitation — HTTP request with an invalid Host header (single slash) targeting the OpenTelemetry Prometheus exporter.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - webserver
rules_count: 2
---

The OpenTelemetry Prometheus exporter is vulnerable to a denial-of-service attack. A single malformed HTTP request sent to the metrics endpoint (default `0.0.0.0:9464`) can crash any Node.js process running the exporter. The vulnerability lies in the lack of error handling when parsing the URL from the HTTP request. Specifically, the `new URL()` constructor within the `_requestHandler` in `PrometheusExporter.ts` throws a `TypeError` when provided with an invalid URI (e.g., `http://`). Because this exception is uncaught, it propagates and terminates the process. The affected packages are `@opentelemetry/exporter-prometheus`, `@opentelemetry/sdk-node`, and `@opentelemetry/auto-instrumentations-node`. This vulnerability exists in versions prior to `@opentelemetry/exporter-prometheus` and `@opentelemetry/sdk-node` version 0.217.0, and `@opentelemetry/auto-instrumentations-node` version 0.75.0.

## Attack Chain

1. An attacker identifies a Node.js application using the OpenTelemetry Prometheus exporter.
2. The attacker crafts a malformed HTTP request containing an invalid URI (e.g., `GET http:// HTTP/1.1`).
3. The attacker sends the malformed request to the application's metrics endpoint (default port 9464).
4. The `PrometheusExporter._requestHandler` receives the request and attempts to parse the URL using `new URL(request.url, this._baseUrl)`.
5. The `URL` constructor throws a `TypeError: Invalid URL` due to the malformed URI.
6. The exception is not caught within the `_requestHandler`, causing it to propagate.
7. The uncaught exception terminates the Node.js process.
8. The application becomes unavailable, resulting in a denial-of-service.

## Impact

Successful exploitation leads to a denial-of-service condition. Any application utilizing the OpenTelemetry Prometheus exporter's built-in server can be crashed by an unauthenticated network packet sent to the metrics port. The vulnerability requires no prior access or privileges and can be triggered remotely, potentially affecting all instances of the application exposing the Prometheus endpoint.

## Recommendation

*   Upgrade `@opentelemetry/exporter-prometheus` and `@opentelemetry/sdk-node` to version 0.217.0 or later to resolve CVE-2026-44902.
*   Upgrade `@opentelemetry/auto-instrumentations-node` to version 0.75.0 or later to resolve CVE-2026-44902.
*   Apply network policies to restrict access to port 9464 (or the configured metrics port) to only trusted Prometheus scrape hosts, as an interim mitigation.
*   Deploy the Sigma rule `Detect OpenTelemetry Prometheus Exporter Malformed HTTP Request` to detect exploitation attempts.
