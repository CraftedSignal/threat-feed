---
title: Unbounded W3C Tracestate Parsing in datadog-opentelemetry
slug: 2026-08-datadog-opentelemetry-dos
description: The datadog-opentelemetry Rust library is vulnerable to a remote denial-of-service attack due to unbounded parsing of the W3C tracestate header, allowing unauthenticated attackers to exhaust CPU and memory resources.
date: "2026-08-29T03:14:08Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:datadog:datadog-opentelemetry:*:*:*:*:*:rust:*:*
tags:
  - denial-of-service
  - rust
  - supply-chain
vendors:
  - Datadog
products:
  - datadog-opentelemetry (0.1.0 - 0.3.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A remote, unauthenticated attacker can send a tracestate header whose dd= member is arbitrarily large, forcing unbounded CPU and memory consumption per request and enabling a remote Denial of Service.
    confidence_band: high
cves:
  - id: CVE-2026-54788
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-gpwf-4h98-v82q
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-54788
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade datadog-opentelemetry to version 0.3.3 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-54788 fix included in 0.3.3
  mitigation_plan:
    - priority: immediate
      action: Set DD_TRACE_PROPAGATION_STYLE_EXTRACT to exclude tracecontext
      owner: Application Security
      addresses: CVE-2026-54788
      evidence: Source provides this as an immediate workaround
---

The datadog-opentelemetry Rust library (versions 0.1.0 through 0.3.2) contains a vulnerability in its implementation of W3C Trace Context propagation. The tracer performs unbounded parsing of the `tracestate` header, specifically when processing the Datadog vendor entry (`dd=...`). This entry contains semicolon-separated key:value pairs which the library stores in a hash map without enforcing a size limit on the input or the resulting structure.

A remote, unauthenticated attacker can exploit this by sending HTTP requests with a maliciously crafted `tracestate` header containing an arbitrarily large number of key:value pairs or an excessively large string. Because `tracecontext` extraction is enabled by default in affected tracers, services using this library are exposed to resource exhaustion. The resulting CPU and memory consumption can lead to a Denial of Service (DoS) for the instrumented application. This issue is tracked as CVE-2026-54788.

## Impact

Successful exploitation leads to a remote Denial of Service (DoS) by saturating server CPU and memory. Any internet-facing service instrumented with the vulnerable library versions is at risk, potentially causing service outages or significant performance degradation across affected microservices and backend systems.

## Recommendation

1. Upgrade `dd-trace-rs` to version 0.3.3 or later to apply the necessary input parsing bounds.
2. If an immediate upgrade is not possible, disable `tracecontext` extraction by setting the `DD_TRACE_PROPAGATION_STYLE_EXTRACT` environment variable to a value that excludes `tracecontext`, such as `datadog`.
3. Implement header size restrictions at the infrastructure level by configuring upstream proxies or web servers to reject requests with excessively large `tracestate` headers.
