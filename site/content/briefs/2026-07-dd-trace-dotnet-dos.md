---
title: Datadog dd-trace-dotnet Improper W3C Baggage Header Parsing Leads to DoS
slug: 2026-07-dd-trace-dotnet-dos
description: A Denial of Service (DoS) vulnerability exists in Datadog tracing libraries (`dd-trace-dotnet`) due to improper parsing of W3C baggage HTTP headers, allowing remote, unauthenticated attackers to send requests with arbitrarily large baggage headers, causing unbounded CPU and memory consumption and leading to service unavailability for any HTTP service instrumented with affected library versions where baggage propagation is enabled by default. The issue, tracked as CVE-2026-50273, is resolved in version 3.43.0 and later.
date: "2026-07-15T23:02:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - vulnerability
  - dot-net
vendors:
  - Datadog
products:
  - Datadog.Trace (< 3.43.0)
  - Datadog.Trace.OpenTracing (< 3.43.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: causing unbounded CPU and memory consumption and enabling a remote Denial of Service against any HTTP service
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-38wr-vpc7-2mp4
---

A high-severity Denial of Service (DoS) vulnerability, identified as CVE-2026-50273, affects Datadog tracing libraries, specifically `dd-trace-dotnet` versions prior to 3.43.0. The vulnerability stems from improper parsing of W3C baggage HTTP headers, where the libraries fail to enforce item-count or byte-size limits during header extraction. While limits were applied during baggage injection, they were not active during extraction, allowing remote, unauthenticated attackers to send specially crafted HTTP requests. These requests contain baggage headers with an arbitrarily large number of comma-separated key-value pairs or a single excessively large value. When the vulnerable tracer attempts to process such headers, it allocates a hash-map entry for each perceived pair, leading to unbounded consumption of CPU and memory resources. This resource exhaustion results in a Denial of Service against any HTTP service instrumented with an affected `dd-trace-dotnet` version, particularly since baggage propagation is enabled by default in most affected tracers.

## Attack Chain

1. Attacker identifies an internet-facing HTTP service instrumented with a vulnerable `dd-trace-dotnet` version (prior to 3.43.0) where W3C baggage propagation is enabled (often by default).
2. Attacker crafts a malicious HTTP request targeting the vulnerable service.
3. The crafted request includes a W3C `baggage` HTTP header containing an arbitrarily large number of comma-separated key-value pairs or a single, extremely large value.
4. The vulnerable `dd-trace-dotnet` library receives the request and initiates the process of parsing and extracting baggage items from the malformed header.
5. Due to the absence of item-count or byte-size limits on the extraction path, the tracer continuously allocates hash-map entries for each item it attempts to extract.
6. This uncontrolled allocation leads to rapid and unbounded consumption of the service's CPU and memory resources.
7. The affected HTTP service experiences severe performance degradation, becomes unresponsive, or crashes entirely, resulting in a Denial of Service for legitimate users.

## Impact

Successful exploitation of CVE-2026-50273 leads to a Denial of Service for any HTTP service instrumented with vulnerable `dd-trace-dotnet` libraries (versions prior to 3.43.0) with default baggage propagation settings. Attackers can leverage this vulnerability to trigger unbounded CPU and memory consumption by sending a single malicious HTTP request containing an oversized W3C baggage header. This results in the service becoming unresponsive or crashing due to resource exhaustion, effectively taking it offline. The impact extends to critical business applications and infrastructure relying on Datadog tracing, leading to significant operational disruption and potential data loss if services are not properly restarted.

## Recommendation

* Upgrade all instances of `dd-trace-dotnet` to version 3.43.0 or later to patch CVE-2026-50273.
* If immediate upgrade is not feasible, disable `baggage` extraction by removing `baggage` from the `DD_TRACE_PROPAGATION_STYLE` environment variable, or `DD_TRACE_PROPAGATION_STYLE_EXTRACT` if set independently.
* Implement measures to cap the maximum HTTP request header size at an upstream proxy or web server (e.g., configure Apache's `LimitRequestFieldSize`, Nginx's `large_client_header_buffers`, or Envoy's `max_request_headers_kb`).
