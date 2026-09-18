---
title: Denial of Service in go-openapi/swag via Stack Overflow
slug: 2026-09-go-openapi-swag-dos
description: The go-openapi/swag library is vulnerable to a stack overflow in its jsonutils component, allowing remote unauthenticated attackers to cause a denial-of-service by submitting deeply nested JSON documents.
date: "2026-09-18T02:01:32Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:go-openapi:swag:*:*:*:*:*:*:*:*
vendors:
  - go-openapi
products:
  - swag (< 0.27.1)
cves:
  - id: CVE-2026-93450
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93450
action_plan:
  priority: elevated
  owners:
    - Development
    - Infrastructure
  immediate_actions:
    - action: Upgrade go-openapi/swag dependency to version 0.27.1 or later
      owner: Development
      due: 48h
      evidence: Source explicitly identifies 0.27.1 as the fix version
  mitigation_plan:
    - priority: immediate
      action: Upgrade go-openapi/swag dependency to 0.27.1 or later
      owner: Development
      addresses: CVE-2026-93450
      evidence: NVD advisory identifies version 0.27.1 as the patch release
---

The go-openapi/swag library, specifically the jsonutils component in versions prior to 0.27.1, contains a critical stack overflow vulnerability. The flaw arises from unbounded recursion during the parsing and serialization of ordered JSON structures, which lacks a defined depth limit. By submitting a specially crafted, deeply nested JSON document to any service or application utilizing the library to process OpenAPI specifications, a remote unauthenticated attacker can trigger a fatal stack overflow. This leads to an immediate crash of the host process, effectively terminating all in-flight requests and causing a denial-of-service condition. Because this library is commonly integrated into API gateways, middleware, and documentation generators, the potential impact across microservices architectures is significant.

## Impact

Successful exploitation results in a persistent denial-of-service for any service using the vulnerable library. The vulnerability is triggered by a single request, meaning minimal resources are required for an attacker to disrupt service availability. All deployments of applications using go-openapi/swag versions before 0.27.1 are susceptible to this vector.

## Recommendation

Prioritized, concrete actions for development and security teams:
- Upgrade the go-openapi/swag dependency to version 0.27.1 or later immediately to include the required depth limiting in the jsonutils component.
- Review all internet-facing services that accept OpenAPI or JSON-based configurations and apply input validation to limit JSON nesting depth as a defense-in-depth measure until the library is patched.
- Implement crash monitoring and automated service restarts in orchestrators (such as Kubernetes) to mitigate the impact of the resulting process termination.
