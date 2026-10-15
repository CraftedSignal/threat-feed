---
title: Uncontrolled Recursion DoS in kin-openapi
slug: 2026-10-kin-openapi-recursion-dos
description: The kin-openapi library lacks cycle detection during runtime schema validation, allowing attackers to trigger an unrecoverable Go runtime stack overflow that terminates the entire host process.
date: "2026-10-15T22:23:51Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:getkin:kin-openapi:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - openapi
vendors:
  - getkin
products:
  - kin-openapi (< 0.149.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: The entire process is terminated, including all goroutines serving unrelated clients.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-g8cf-rcjf-c8cf
  - https://github.com/getkin/kin-openapi/pull/1123
---

The kin-openapi library (versions prior to 0.149.0) contains a critical flaw in its runtime schema validation logic. While the library's spec-loader and `Schema.validate()` method implement cycle detection to handle circular references in OpenAPI schemas, the runtime validators `VisitJSON` (used for response validation) and `decodeValue` (used for request parameter decoding) lack these protections.

When a circular combinator chain (such as `allOf`, `anyOf`, or `oneOf`) is encountered during request or response processing, the library enters an infinite recursion loop. In Go, this eventually exhausts the goroutine stack, triggering a fatal `runtime: goroutine stack exceeds ... limit` error. Because this is a fatal runtime error rather than a panic, it cannot be intercepted by `recover()` blocks in `net/http` handlers. Consequently, any request triggering this path causes the entire application process to crash, resulting in a total denial-of-service for all clients sharing that process. This affects any application using kin-openapi for request/response validation, whether the circular schema is provided by a malicious actor or exists as a latent bug in a legitimate API specification.

## Attack Chain

1. Attacker identifies an application endpoint utilizing `kin-openapi` for request or response validation.
2. Attacker crafts a malicious OpenAPI specification, or leverages an existing one, containing a circular combinator reference (e.g., a `Schema` object with an `allOf` field pointing back to itself).
3. The target application loads the malicious specification into memory via the `kin-openapi` loader, which treats the circularity as a valid data structure.
4. The application receives a legitimate HTTP request routed to an endpoint governed by the circular schema definition.
5. The library's `openapi3filter` or `VisitJSON` component processes the input against the circular combinator chain.
6. The lack of stack-based cycle detection causes the recursion to continue indefinitely.
7. The Go runtime triggers a fatal stack overflow error.
8. The entire application process terminates, resulting in a successful denial-of-service.

## Impact

The vulnerability results in an unrecoverable, process-wide denial-of-service. Because the Go runtime error is fatal, all concurrent connections served by the same process are immediately dropped. The threat is particularly severe for API gateways, mock servers, or any infrastructure that dynamically loads or validates OpenAPI specifications from user-supplied inputs. Even in deployments using static, trusted specifications, the presence of a circular reference leads to a persistent, triggered crash upon any interaction with the affected endpoint.

## Recommendation

* Update `kin-openapi` to version 0.149.0 or later, which implements mandatory cycle detection in both `VisitJSON` and `decodeValue` paths.
* Implement strict validation for any OpenAPI specifications loaded from untrusted or external sources before they are used for runtime validation.
* In environments where immediate patching is not possible, implement an upstream WAF rule to scan for and block YAML/JSON inputs containing recursive `allOf`, `anyOf`, or `oneOf` structures.
* Deploy monitoring to identify and alert on `fatal error: stack overflow` entries in application log files, which signal active exploitation or the presence of a broken schema.
