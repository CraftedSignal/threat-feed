---
title: Micronaut TimeConverterRegistrar Memory Exhaustion via Accept-Language Header
slug: 2024-11-micronaut-dos
description: Micronaut's `TimeConverterRegistrar` has an unbounded `formattersCache` that allows memory exhaustion via a crafted `Accept-Language` header, where an unauthenticated attacker can crash the JVM by sending requests with novel locale tags to `@Format`-annotated endpoints, growing the cache until heap memory is exhausted, affecting Micronaut applications with `micronaut-context` versions 4.3.0 and above, up to but not including 4.10.22.
date: "2024-11-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - memory-exhaustion
  - micronaut
vendors:
  - Micronaut
products:
  - micronaut-context
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-8hjv-92q9-g4xj
rules:
  - title: Micronaut Excessive Unique Accept-Language Headers
    description: Detects a high volume of requests with unique Accept-Language headers, potentially indicating a memory exhaustion attack against Micronaut's TimeConverterRegistrar.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Micronaut Accept-Language Locale Parsing
    description: Detects requests where the Accept-Language header is parsed, indicating potential locale-based vulnerabilities.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
  - title: Micronaut endpoint with @Format annotation
    description: Detects access to specific endpoints potentially susceptible to the TimeConverterRegistrar vulnerability based on cs-uri-query.
    platform: sigma
    severity: informational
    tactics:
      - reconnaissance
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 3
---

Micronaut's `TimeConverterRegistrar` component contains a vulnerability that can lead to denial-of-service (DoS). The `formattersCache` within `TimeConverterRegistrar` is an unbounded `ConcurrentHashMap` that caches `DateTimeFormatter` instances. The cache key is derived from the `@Format` annotation pattern concatenated with the locale obtained from the HTTP `Accept-Language` header. By sending HTTP requests with arbitrary BCP 47 private-use extensions in the `Accept-Language` header (e.g., `en-x-a001`, `en-x-a002`), an unauthenticated attacker can generate a large number of unique cache keys. This leads to uncontrolled memory consumption, eventually exhausting the available heap memory and causing the JVM to crash with an `OutOfMemoryError`. The vulnerability affects Micronaut applications that expose endpoints with `@Format`-annotated temporal parameters and exists in `micronaut-context` versions 4.3.0 and above, up to but not including 4.10.22. This is similar to GHSA-2hcp-gjrf-7fhc but affects a different cache.

## Attack Chain

1. An attacker sends an HTTP request to a Micronaut server.
2. The request includes a crafted `Accept-Language` header with a novel BCP 47 private-use extension (e.g., `en-x-attacker`).
3. Micronaut's `HttpHeaders.findAcceptLanguage()` parses the `Accept-Language` header and extracts the locale using `Locale.forLanguageTag()`.
4. The extracted locale is passed to `AbstractRouteMatch.newContext()` and stored in the `ConversionContext`.
5. The request is routed to an endpoint with a `@Format`-annotated temporal parameter.
6. `TimeConverterRegistrar.getFormatter(pattern, context)` is called to retrieve a `DateTimeFormatter` for the given pattern and locale.
7. Since the locale is novel, a new `DateTimeFormatter` is created and added to the unbounded `formattersCache` with the concatenated `pattern + locale` as the key.
8. The attacker repeats this process with many unique `Accept-Language` values, causing the `formattersCache` to grow without bounds, leading to an `OutOfMemoryError` and crashing the JVM, resulting in denial of service.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to crash any Micronaut server that exposes an endpoint with a `@Format`-annotated temporal type parameter. The memory consumption grows linearly with the number of unique `Accept-Language` values sent by the attacker. Due to the large number of possible BCP 47 private-use extensions, attackers can easily exhaust server memory. This can lead to denial of service, disrupting legitimate users. The `TimeConverterRegistrar` is active in all Micronaut HTTP server applications by default.

## Recommendation

*   Apply the fix pattern used for GHSA-2hcp-gjrf-7fhc by replacing the unbounded `ConcurrentHashMap` with a bounded `ConcurrentLinkedHashMap`.
*   Upgrade to `micronaut-context` version 4.10.22 or later to receive the patched version.
*   Monitor web server logs for a high volume of requests with unique `Accept-Language` headers using the provided Sigma rule.
*   Consider implementing rate limiting on requests with unique `Accept-Language` headers to mitigate the risk of exploitation.
