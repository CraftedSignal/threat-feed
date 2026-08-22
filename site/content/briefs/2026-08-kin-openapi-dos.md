---
title: Uncontrolled Resource Consumption in kin-openapi deepObject Decoder
slug: 2026-08-kin-openapi-dos
description: An unauthenticated remote attacker can cause a denial-of-service via memory exhaustion by supplying a large integer index in a 'deepObject' style query parameter.
date: "2026-08-22T01:17:17Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - memory-exhaustion
  - vulnerability
  - golang
vendors:
  - getkin
products:
  - kin-openapi (v0.124.0 - v0.141.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated client can force multi-gigabyte heap allocation with a single, tiny HTTP request, reliably triggering an OOM kill.
    confidence_band: high
---

The `openapi3filter` component within `kin-openapi` (versions `v0.124.0` through `v0.141.0`) is vulnerable to uncontrolled resource consumption. When the library processes query parameters serialized with `style: deepObject`, it attempts to reconstruct arrays from bracketed indices (e.g., `param[items][50000000]=x`). The decoder materializes the full array based on the highest index provided by the client before any schema validation occurs. Consequently, a small, 24-byte HTTP request can force the application to allocate gigabytes of memory, leading to an OOM (Out of Memory) crash. Because validation logic like `maxItems` runs after this materialization process, it cannot prevent the initial memory exhaustion. This vulnerability affects any service using `kin-openapi` for request validation that exposes an OpenAPI operation with a `deepObject` array parameter.

## Attack Chain

1. Attacker identifies an endpoint utilizing `kin-openapi` that processes `deepObject` query parameters containing an array schema.
2. Attacker crafts a minimal HTTP GET request containing a `deepObject` query parameter with a high-value integer index (e.g., `param[items][50000000]=x`).
3. The `kin-openapi` router identifies the route and passes the request to `openapi3filter.ValidateRequest`.
4. The decoder parses the query string and enters `sliceMapToSlice`, which identifies the maximum user-supplied index.
5. The library performs an unbounded loop from 0 to the attacker-supplied maximum index to initialize a `[]any` slice, allocating memory for every index in the range.
6. The `buildResObj` function performs a second, equally-sized allocation for the final result array.
7. The application service crashes due to excessive heap allocation, causing a denial-of-service.

## Impact

Successful exploitation allows an unauthenticated remote attacker to cause a denial-of-service by forcing an application crash. The amplification factor is extreme; a 24-byte request can force an allocation of ~6.1 GiB. This vulnerability impacts any service infrastructure relying on `kin-openapi` for API request validation, potentially leading to widespread service unavailability for affected applications.

## Recommendation

1. Identify all services utilizing `kin-openapi` versions between `v0.124.0` and `v0.141.0` that expose `deepObject` query parameters.
2. Upgrade the `kin-openapi` dependency to a patched version once available from the maintainers.
3. Implement a Web Application Firewall (WAF) or upstream proxy to drop requests containing extremely large integer values within bracketed query parameters (e.g., `\[[0-9]{7,}\]`).
4. Monitor application server logs for frequent crash loops or OOM-related restart events following the deployment of this library.
