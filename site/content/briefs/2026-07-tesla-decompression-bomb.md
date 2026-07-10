---
title: Tesla Elixir Client Decompression Bomb (CVE-2026-48594)
slug: 2026-07-tesla-decompression-bomb
description: A critical vulnerability, CVE-2026-48594, in the Tesla Elixir HTTP client library allows an attacker to cause a denial of service by serving a specially crafted HTTP response with multiple `content-encoding` headers that, when processed by vulnerable versions (0.6.0 through 1.18.2) of the client using `Tesla.Middleware.DecompressResponse` or `Tesla.Middleware.Compression`, leads to exponential memory expansion and application crashes.
date: "2026-07-10T00:08:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - resource-exhaustion
  - denial-of-service
  - library-vulnerability
  - elixir
vendors:
  - elixir-tesla
products:
  - tesla (>= 0.6.0, < 1.18.3)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Resource Exhaustion
    evidence: Repeated or sufficiently large requests exhaust available memory and crash or freeze the node.
    confidence_band: high
cves:
  - id: CVE-2026-48594
    epss: 0.00329
references:
  - https://github.com/advisories/GHSA-mc85-72gr-vm9f
  - https://github.com/elixir-tesla/tesla/commit/5bd90bb5cf0d15e375edc2a66fa322292940fce2
  - https://github.com/elixir-tesla/tesla/commit/340f75b5d191dc747ef7ac6365bd002d1cd55a9d
---

A high-severity vulnerability, tracked as CVE-2026-48594, exists in the Tesla Elixir HTTP client library, specifically affecting versions 0.6.0 through 1.18.2. This flaw, dubbed a "decompression bomb," can be exploited by an attacker who controls a server that a vulnerable Tesla client contacts, or via a redirect. The vulnerability arises when the `Tesla.Middleware.DecompressResponse` or `Tesla.Middleware.Compression` middleware component eagerly decompresses HTTP response bodies without any size limits. An attacker can craft a minuscule gzip-encoded payload coupled with multiple `content-encoding` headers (e.g., `gzip, gzip, gzip, gzip`), which, upon recursive decompression, expands exponentially into gigabytes of data on the BEAM heap. This excessive memory consumption inevitably leads to the client application crashing or freezing, effectively causing a denial of service. Defenders must ensure that applications utilizing the affected `tesla` library are patched to version 1.18.3 or later to mitigate this risk.

## Attack Chain

1. An attacker gains control of a server or compromises a legitimate server that a victim's Tesla client application is likely to contact.
2. The attacker configures the server to serve a specially crafted HTTP response.
3. The crafted response includes a tiny gzip-compressed payload that is designed to expand significantly upon decompression.
4. Crucially, the response features multiple `content-encoding` headers, such as `gzip, gzip, gzip, gzip`, to trigger recursive decompression.
5. A legitimate application, running an affected `tesla` library version (0.6.0 to 1.18.2) and configured with `Tesla.Middleware.DecompressResponse` or `Tesla.Middleware.Compression`, makes an HTTP request to the attacker-controlled server.
6. The `tesla` client receives the malicious HTTP response from the attacker's server.
7. The `decompress_body/2` function within the `tesla` middleware attempts to decompress the response recursively for each `content-encoding` token, without any output size validation.
8. This process exponentially inflates the small payload into gigabytes of data within the BEAM heap, exhausting the application's memory resources and causing it to crash or freeze, resulting in a denial of service.

## Impact

The impact of CVE-2026-48594 is a denial of service (DoS) for any application utilizing the affected `tesla` client library (versions 0.6.0 through 1.18.2) with the `Tesla.Middleware.DecompressResponse` or `Tesla.Middleware.Compression` middleware. The attacker's objective is to render the targeted application unusable by forcing it to consume all available memory. A successful attack can lead to application downtime, data processing failures, and disruption of critical services, potentially affecting any sector relying on Elixir applications performing HTTP requests with the vulnerable middleware. This vulnerability carries a high severity CVSS v4.0 score of 8.2.

## Recommendation

* **Patch CVE-2026-48594** by upgrading the `erlang/tesla` package to version 1.18.3 or later immediately.
* Review applications for the inclusion of `Tesla.Middleware.DecompressResponse` or `Tesla.Middleware.Compression` in their Tesla middleware pipeline. If present, ensure they are running patched versions.
* Implement application-level monitoring for abnormal and sudden increases in memory consumption by Elixir applications, especially those making outbound HTTP requests, to detect potential exploitation attempts.
