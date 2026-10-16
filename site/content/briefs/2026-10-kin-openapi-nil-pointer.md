---
title: Denial of Service in kin-openapi via Malformed OpenAPI Specifications
slug: 2026-10-kin-openapi-nil-pointer
description: A nil-pointer dereference vulnerability (CVE-2026-100349) in kin-openapi causes a process crash when validating response headers that declare 'content' instead of 'schema'.
date: "2026-10-16T22:28:43Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:kin-openapi:kin-openapi:*:*:*:*:*:*:*:*
products:
  - kin-openapi (<= 0.145.0)
cves:
  - id: CVE-2026-100349
references:
  - https://github.com/advisories/GHSA-74vm-87hj-r66f
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100349
action_plan:
  priority: elevated
  owners:
    - Development Teams
    - Security Engineering
  immediate_actions:
    - action: Upgrade kin-openapi to 0.146.0 or later
      owner: Development Teams
      due: 48h
      evidence: Source advisory identifies v0.145.0 and earlier as vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Identify and update OpenAPI specifications using content-typed response headers
      owner: Development Teams
      addresses: CVE-2026-100349
      evidence: Source suggests using schema instead of content on response headers as a workaround.
---

A nil-pointer dereference vulnerability exists in `github.com/getkin/kin-openapi` (versions <= v0.145.0) within the `ValidateResponse` function. When an OpenAPI specification defines a response header using the `content` field without an explicit `schema`, the library attempts to dereference a nil pointer during the validation process. 

This issue is significant because `doc.Validate()` incorrectly marks such specifications as valid, allowing them to be loaded into memory. Once an application receives a request that exercises a route associated with the malformed header, the process triggers a runtime panic and terminates. Because the crash occurs on every call to the affected route, this results in an effective denial-of-service (DoS) condition. The vulnerability is triggered automatically during validation logic and does not require a complex malicious payload, only a specification that utilizes the `content` keyword for response headers.

## Impact

The vulnerability results in a persistent DoS condition for any service utilizing `kin-openapi` to validate responses against an OpenAPI specification containing `content`-typed response headers. Any traffic directed to the affected route will cause the underlying Go service to panic and crash. While individual services may recover upon restart, the crash is deterministic and will recur immediately upon the next request to that route, necessitating the removal or modification of the OpenAPI specification to restore availability.

## Recommendation

* Prioritize updating `github.com/getkin/kin-openapi` to a version released after v0.145.0 that includes the nil-pointer guard.
* If immediate patching is not possible, identify and manually modify OpenAPI specifications to use `schema` instead of `content` for all response headers.
* As a temporary mitigation, exclude routes containing `content`-typed response headers from `ValidateResponse` processing.
* Implement automated linter checks in your CI/CD pipeline to flag OpenAPI specifications that declare `content` within `headers` objects to prevent deployment of vulnerable configurations.
