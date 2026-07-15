---
title: Datadog dd-trace-py Improper Parsing of W3C Baggage Headers Leads to DoS
slug: 2026-07-dos-dd-trace-py
description: The Datadog dd-trace-py tracing library, versions prior to 4.8.2, is vulnerable to a Denial of Service (DoS) attack due to improper parsing of W3C baggage HTTP headers, which fails to enforce item-count or byte-size limits on the extraction path, allowing an unauthenticated attacker to send a request with an arbitrarily large baggage header causing unbounded CPU and memory consumption.
date: "2026-07-15T22:57:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - python
  - supply-chain
vendors:
  - Datadog
products:
  - dd-trace-py < 4.8.2
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A remote, unauthenticated attacker can send a request whose baggage header contains an arbitrarily large number of comma-separated key-value pairs (or a single very large value). The tracer allocates a hash-map entry for each pair on every request, causing unbounded CPU and memory consumption and enabling a remote Denial of Service against any HTTP service that has the baggage propagation style enabled.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-mw54-j2v2-42hr
  - https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-mh2q-q3fh-2475
  - https://github.com/open-telemetry/opentelemetry-dotnet/security/advisories/GHSA-g94r-2vxg-569j
---

The `dd-trace-py` library, a Python tracing library for Datadog, versions prior to 4.8.2, contains a Denial of Service (DoS) vulnerability (CVE-2026-50271). This vulnerability stems from improper parsing of W3C baggage HTTP headers. While the library enforces `DD_TRACE_BAGGAGE_MAX_ITEMS` (default 64) and `DD_TRACE_BAGGAGE_MAX_BYTES` (default 8192) limits during baggage *injection*, these limits are not applied during baggage *extraction*. A remote, unauthenticated attacker can exploit this by sending an HTTP request containing a `baggage` header with an arbitrarily large number of comma-separated key-value pairs or a single, excessively long value. The vulnerable tracer will allocate a hash-map entry for each pair on every request without bounds, leading to severe CPU and memory consumption. This can result in a remote DoS against any internet-facing HTTP service instrumented with an affected `dd-trace-py` version, especially since baggage propagation is typically enabled by default. The issue was published on 2026-07-15.

## Attack Chain

1. An unauthenticated attacker crafts an HTTP request targeting an internet-facing application instrumented with `dd-trace-py`.
2. The attacker includes a `W3C baggage` HTTP header in the request, designed to contain an excessive number of comma-separated key-value pairs or a single, extremely long value.
3. The vulnerable application, running `dd-trace-py` versions prior to 4.8.2 with default baggage propagation settings, receives the malformed request.
4. The `dd-trace-py` library begins to parse the incoming `baggage` header. During this extraction process, it fails to enforce configured limits on item count or byte size.
5. This unbounded parsing leads to the allocation of an arbitrarily large number of hash-map entries and excessive processing, consuming high CPU and memory resources on the server.
6. The server's computational and memory resources become exhausted, causing the instrumented application to become unresponsive and resulting in a Denial of Service (DoS).

## Impact

Successful exploitation of CVE-2026-50271 leads to a Denial of Service against any HTTP service instrumented with vulnerable `dd-trace-py` versions. The impact includes unbounded CPU and memory consumption on the targeted server, rendering the application unresponsive and unavailable to legitimate users. Since baggage propagation is often enabled by default, a wide range of internet-facing services could be vulnerable without explicit configuration changes or upgrades. The attack is unauthenticated, allowing any remote actor to trigger the DoS condition.

## Recommendation

* Upgrade the `dd-trace-py` library to version 4.8.2 or later immediately to patch CVE-2026-50271.
* If immediate upgrade is not possible, disable `baggage` extraction by removing `baggage` from the `DD_TRACE_PROPAGATION_STYLE` environment variable, or from `DD_TRACE_PROPAGATION_STYLE_EXTRACT` if set independently.
* Implement measures at an upstream proxy or web server to cap the maximum HTTP request header size (e.g., configure Apache's `LimitRequestFieldSize`, Nginx's `large_client_header_buffers`, or Envoy's `max_request_headers_kb`).
