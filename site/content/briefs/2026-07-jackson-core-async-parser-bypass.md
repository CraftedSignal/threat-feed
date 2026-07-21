---
title: Jackson-core Async Parser Max Number Length Bypass via Chunked Digit Accumulation
slug: 2026-07-jackson-core-async-parser-bypass
description: An incomplete fix for GHSA-72hv-8253-57qq in `jackson-core` versions 2.18.6, 2.21.1, and potentially 3.0.x/3.1.x, allows attackers to bypass `maxNumberLength` constraints in the non-blocking JSON parser by streaming JSON numbers in small chunks, leading to unbounded memory accumulation and denial of service in reactive applications.
date: "2026-07-21T22:01:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - java
  - json
  - serialization
  - memory-exhaustion
  - denial-of-service
vendors:
  - FasterXML
products:
  - jackson-core (2.18.6)
  - jackson-core (2.21.1)
  - jackson-core (3.0.x)
  - jackson-core (3.1.x)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Application Denial of Service
    evidence: 'Memory Exhaustion: Unbounded allocation in TextBuffer from excessively long numbers... OOM the JVM... denial-of-service in applications'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-r7wm-3cxj-wff9
---

A critical vulnerability exists in `jackson-core` versions 2.18.6 and 2.21.1 (and presumed in 3.0.x/3.1.x), which represents an incomplete fix for GHSA-72hv-8253-57qq, initially published in February 2026. This flaw primarily impacts reactive applications that utilize `jackson-core`'s non-blocking JSON parser, such as those built with Spring WebFlux, Quarkus, Helidon, or Vert.x JSON. The vulnerability allows an attacker to bypass the configured `maxNumberLength` constraint by sending JSON containing a large number in many small, non-terminating chunks. The parser's internal `_textBuffer` then continues to accumulate digits without proper validation, expanding up to the much larger `maxStringLength` (default 20 MiB), which is a roughly 20,000x amplification over the default `maxNumberLength` (1000). This uncontrolled memory growth can lead to severe memory exhaustion and denial-of-service conditions, impacting the availability of targeted applications.

## Attack Chain

1. An attacker initiates an HTTP request to a vulnerable reactive application, sending a partial JSON payload that begins a large numeric value (e.g., `{"value":1`).
2. The application's `jackson-core` non-blocking JSON parser begins processing the initial data chunk.
3. The attacker continues to send subsequent HTTP request chunks, each containing a small segment of digits, without ever sending a character that would terminate the number (e.g., '.', 'e', 'E', or '}' for object closure).
4. For each incoming chunk of digits, the non-blocking parser's `_textBuffer.expandCurrentSegment()` continuously allocates more memory to accumulate the digits.
5. Due to an incomplete fix for GHSA-72hv-8253-57qq, the critical `validateIntegerLength` check is not invoked when the parser runs out of input mid-integer, allowing the buffer to grow far beyond the intended `maxNumberLength`.
6. This uncontrolled memory accumulation continues until the allocated memory reaches `maxStringLength` (default 20 MiB) or the application's Java Virtual Machine (JVM) experiences an Out-Of-Memory (OOM) error.
7. The targeted application becomes unresponsive or crashes due to resource exhaustion, resulting in a denial-of-service for legitimate users.

## Impact

Applications employing `jackson-core`'s non-blocking JSON parser in reactive frameworks are critically vulnerable to denial-of-service (DoS) attacks. This includes widely used environments such as Spring WebFlux, Quarkus, Helidon, and Vert.x JSON. Attackers can exploit this bypass to force the application's JVM to allocate excessive memory, potentially leading to Out-Of-Memory (OOM) errors and application crashes. The `maxNumberLength` configuration, intended to prevent such attacks, is effectively ignored, allowing memory consumption to reach up to `maxStringLength` (20 MiB per connection by default), which represents a ~20,000-fold increase over the expected limit. This resource exhaustion severely impacts the availability and stability of affected services.

## Recommendation

* Upgrade `jackson-core` to a patched version immediately upon its release. Monitor the project's advisories for the official fix.
* If an immediate upgrade is not possible, consider implementing a custom patch derived from the fix branch to address the missing validation calls in `NonBlockingUtf8JsonParserBase.java`.
* Review and configure `StreamReadConstraints` in `JsonFactory` builder to enforce appropriate `maxStringLength` values. While this is a workaround for the number length issue, it can mitigate the overall memory ceiling.
* Enable application-level logging for `StreamConstraintsException` events, particularly those related to `Number value length`, to identify and alert on attempted exploitation or abnormal large number processing.
