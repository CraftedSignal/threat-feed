---
title: Datadog dd-trace-java DoS Vulnerability via W3C Baggage Headers
slug: 2026-07-dos-dd-trace-java
description: A denial-of-service vulnerability, CVE-2026-50270, exists in Datadog tracing libraries (dd-trace-java prior to version 1.62.0) that implement W3C baggage propagation. Remote, unauthenticated attackers can exploit this by sending HTTP requests with W3C baggage headers containing an arbitrarily large number of comma-separated key-value pairs. The tracer, when extracting these headers, fails to enforce item-count or byte-size limits, leading to unbounded CPU and memory consumption as it allocates hash-map entries for each pair, thereby causing a denial of service against the instrumented HTTP service.
date: "2026-07-15T22:55:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - java
  - vulnerability
  - w3c
  - datadog
vendors:
  - Datadog
products:
  - dd-java-agent (< 1.62.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: causing unbounded CPU and memory consumption and enabling a remote Denial of Service against any HTTP service
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-74xj-wh4w-vqxc
  - https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-mh2q-q3fh-2475
  - https://github.com/open-telemetry/opentelemetry-dotnet/security/advisories/GHSA-g94r-2vxg-569j
---

A high-severity denial-of-service vulnerability, tracked as CVE-2026-50270, affects Datadog's `dd-trace-java` library versions prior to 1.62.0. This flaw stems from improper parsing of W3C baggage HTTP headers without enforcing item-count or byte-size limits during the extraction process. While limits exist for baggage injection, they are not applied during extraction. A remote, unauthenticated attacker can exploit this by sending a specially crafted HTTP request containing an oversized or malformed W3C `baggage` header. This malicious header, when processed by the vulnerable tracer, triggers unbounded CPU and memory consumption as the library attempts to allocate hash-map entries for each of the numerous key-value pairs, leading to a denial of service against any internet-facing HTTP service instrumented with the affected `dd-trace-java` versions. W3C baggage propagation is often enabled by default, increasing the attack surface.

## Attack Chain

1. An attacker identifies an internet-facing Java application instrumented with a vulnerable `dd-trace-java` version (prior to 1.62.0) that has W3C baggage propagation enabled.
2. The attacker crafts a malicious HTTP request, including a W3C `baggage` header containing an excessively large number of comma-separated key-value pairs or a single extremely long value.
3. The crafted HTTP request is sent by the attacker to the target application's exposed HTTP endpoint.
4. The vulnerable `dd-trace-java` library intercepts the incoming request and attempts to parse the malformed `baggage` header for distributed tracing propagation.
5. Due to the lack of item-count or byte-size limits on the extraction path, the library consumes an unbounded amount of CPU and memory resources while processing the oversized header.
6. This uncontrolled resource consumption leads to significant CPU utilization and memory exhaustion on the application server.
7. The server's resources are depleted, resulting in a denial-of-service condition, making the application unresponsive and unavailable to legitimate users.

## Impact

The successful exploitation of CVE-2026-50270 results in a remote denial-of-service (DoS) against affected HTTP services. Attackers can render applications unresponsive and unavailable to legitimate users by consuming all available CPU and memory resources. Since the vulnerability is exploitable by remote, unauthenticated attackers, it poses a significant risk to any internet-facing service utilizing `dd-trace-java` versions prior to 1.62.0, especially when W3C baggage propagation is enabled by default. There are no reported specific victim counts or sectors, but any organization using the vulnerable library is at risk.

## Recommendation

* Upgrade the `dd-trace-java` library to version 1.62.0 or later immediately to patch CVE-2026-50270.
* If immediate upgrade is not possible, disable `baggage` extraction by removing `baggage` from the `DD_TRACE_PROPAGATION_STYLE` environment variable (or `DD_TRACE_PROPAGATION_STYLE_EXTRACT` if set independently).
* Implement maximum HTTP request header size limits at an upstream proxy or web server (e.g., Apache's `LimitRequestFieldSize`, Nginx's `large_client_header_buffers`, or Envoy's `max_request_headers_kb`) as a compensatory control against oversized W3C baggage headers.
