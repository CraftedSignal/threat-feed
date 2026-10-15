---
title: Denial of Service via Nil-Pointer Dereference in kin-openapi
slug: 2026-10-kin-openapi-nil-panic
description: An incomplete fix for an OpenAPI 3.1 validation flaw allows unauthenticated attackers to trigger process-crashing nil-pointer dereferences in kin-openapi by supplying array schemas without an 'items' keyword.
date: "2026-10-15T22:23:45Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:kin-openapi:kin-openapi:*:*:*:*:*:*:*:*
vendors:
  - kin-openapi
products:
  - kin-openapi (>= 0.136.0, < 0.149.0)
cves:
  - id: CVE-2026-100353
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-vrcc-3ch7-hppw
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100353
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade kin-openapi to v0.149.0 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-100353 remediation documentation.
  mitigation_plan:
    - priority: immediate
      action: Deploy panic recovery middleware for Go HTTP services
      owner: Application Security
      addresses: CVE-2026-100353
      evidence: Source analysis of net/http panic behavior.
---

The kin-openapi library contains an unpatched denial-of-service vulnerability (CVE-2026-100353) stemming from an incomplete fix for a previously identified nil-pointer dereference. Under OpenAPI 3.1 and JSON Schema 2020-12, it is syntactically valid to define an array schema that omits the 'items' keyword. However, the `openapi3filter` component fails to properly validate the presence of the 'items' property before dereferencing it during the decoding process.

The vulnerability manifests in three distinct paths: query parameters with array types, 'deepObject' query parameters containing array properties, and URL-encoded request bodies where arrays are nested within 'allOf', 'anyOf', or 'oneOf' constructs. An unauthenticated attacker can exploit this by crafting a request that matches these specific schema conditions. Depending on the application's runtime architecture, this causes either the immediate termination of the request-handling goroutine or a full process crash, leading to a denial-of-service condition for the affected service. The vulnerability affects all versions of kin-openapi from 0.136.0 up to, but not including, 0.149.0.

## Impact

The impact of this vulnerability ranges from per-request connection drops to full-process crashes. In standard Go `net/http` implementations, the panic is recovered per-connection, resulting in service degradation. In environments utilizing 'fasthttp', 'connect' adapters, or custom application-managed goroutines, a single malformed request can result in an unrecoverable process crash and total service unavailability. This vulnerability is applicable to any microservice or API gateway utilizing kin-openapi for request validation.

## Recommendation

Prioritized actions for detection and remediation:

- Upgrade the `github.com/getkin/kin-openapi` dependency to version 0.149.0 or later immediately to incorporate the required nil-pointer checks in `urlValuesDecoder.parseArray` and `buildResObj`.
- Perform a code audit of Go-based API services to identify ingestion points using `openapi3filter.ValidateRequest` where the application does not have a global panic recovery mechanism.
- Implement global panic recovery middleware in all Go HTTP servers utilizing kin-openapi to mitigate the risk of full-process termination until patches can be deployed.
