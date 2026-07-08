---
title: Zalando Skipper OPA Policy Bypass via Chunked Encoding
slug: 2026-07-skipper-opa-bypass
description: 'A critical vulnerability in `zalando/skipper`''s OpenPolicyAgent integration, tracked as GHSA-659f-rgp5-w4wf, allows attackers to bypass `opaAuthorizeRequestWithBody` policies using HTTP/1.1 `Transfer-Encoding: chunked` or HTTP/2 requests lacking a `content-length` pseudo-header, leading to unauthorized access to upstream services with uninspected payloads.'
date: "2026-07-08T20:27:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - api-gateway
  - security-bypass
  - opa
  - network
vendors:
  - Zalando
products:
  - skipper (<= v0.26.8)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: When the opaAuthorizeRequestWithBody filter is configured, the OpenPolicyAgentInstance.ExtractHttpBodyOptionally helper produces an empty raw_body for any request whose Content-Length header is missing, while the underlying chunked body still flows through to the upstream service. Rego policies that gate on input.parsed_body evaluate against an empty document, treat the forbidden field as absent, and authorize the request.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-659f-rgp5-w4wf
rules:
  - title: Detect Skipper OPA Bypass Attempt (Chunked Encoding)
    description: 'Detects exploitation attempts of GHSA-659f-rgp5-w4wf where an attacker uses Transfer-Encoding: chunked to bypass OPA body inspection in Zalando Skipper. This rule looks for requests to paths typically protected by OPA that contain both chunked encoding and suspicious content (e.g., admin=true).'
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.009
    data_sources:
      - webserver
rules_count: 1
---

A significant vulnerability (GHSA-659f-rgp5-w4wf) has been identified in `zalando/skipper` versions `<= v0.26.8` that allows threat actors to bypass security policies enforced by the `opaAuthorizeRequestWithBody` filter. This bypass occurs when HTTP/1.1 requests use `Transfer-Encoding: chunked` or HTTP/2 requests omit the `content-length` pseudo-header. Under these conditions, the `OpenPolicyAgentInstance.ExtractHttpBodyOptionally` helper in Skipper incorrectly produces an empty `raw_body` for OpenPolicyAgent (OPA) policies, even though the full, potentially malicious, body is forwarded to the upstream service. This means OPA policies designed to inspect and deny requests based on body content (e.g., for `admin=true` fields, content moderation, or schema validation) will evaluate against an empty document and typically default to allowing the request, effectively neutralizing a critical layer of defense. The vulnerability affects operators relying on Skipper to protect private upstream services using body-content checks.

## Attack Chain

1. **Attacker identifies Skipper instance**: An attacker identifies a `zalando/skipper` API Gateway instance protecting a backend service, configured with the `opaAuthorizeRequestWithBody` filter.
2. **Attacker crafts malicious HTTP request**: The attacker prepares an HTTP POST request containing a payload intended to be blocked by an OPA policy (e.g., `{"admin":true}` to gain administrative privileges).
3. **Applies bypass framing**: The attacker sends the request using HTTP/1.1 with `Transfer-Encoding: chunked` headers or as an HTTP/2 request without a `Content-Length` pseudo-header.
4. **Skipper receives and parses request**: The `zalando/skipper` instance receives the request. Due to the specific framing, Go's `net/http` parser sets `req.ContentLength = -1`.
5. **OPA body extraction fails**: The `ExtractHttpBodyOptionally` function, which is supposed to buffer the body for OPA, checks `req.ContentLength <= maxBodyBytes`. While `-1` passes this check, the subsequent `fillBuffer` loop's condition `int64(m.bodyBuffer.Len()) < expectedSize` (`0 < -1`) is immediately false, preventing any body data from being read. An empty `raw_body` is then passed to the OPA SDK.
6. **OPA policy grants unauthorized access**: The OPA policy, expecting to evaluate `input.parsed_body` against the actual request body, instead receives an empty document. If the policy is designed to deny based on specific content (e.g., `input.parsed_body.admin == true`), it will default to "allow" because the condition is not met in the empty input.
7. **Skipper forwards full payload**: Despite the OPA policy effectively being bypassed, Skipper proceeds to forward the *original, full, and uninspected malicious payload* (e.g., `{"admin":true}`) to the backend upstream service.
8. **Upstream processes unauthorized request**: The upstream service receives and processes the unauthorized request and payload, potentially leading to privilege escalation, data modification, or remote code execution, depending on the backend's vulnerabilities.

## Impact

This vulnerability allows for a complete bypass of critical security controls implemented via OpenPolicyAgent for body content inspection. Organizations using `zalando/skipper` with `opaAuthorizeRequestWithBody` policies to enforce granular authorization, content moderation, or schema validation for incoming requests are at risk. A successful exploitation enables unauthenticated attackers to send arbitrary payloads that OPA policies were explicitly designed to block, potentially leading to unauthorized data access, privilege escalation, command injection, or other severe compromises of protected backend services. There is no observed victim count or specific sector targeting mentioned, but any organization deploying Skipper as an API gateway is affected.

## Recommendation

* Upgrade `zalando/skipper` to a version that contains the fix for GHSA-659f-rgp5-w4wf immediately upon availability.
* Review all OPA policies utilizing `input.parsed_body` with the `opaAuthorizeRequestWithBody` filter to understand their susceptibility to this bypass.
* Deploy the Sigma rule below to detect attempts to use `Transfer-Encoding: chunked` in conjunction with body content that would typically be denied by OPA policies.
* Ensure webserver logs or API gateway logs capture HTTP headers, specifically `Transfer-Encoding`, for POST requests to sensitive endpoints.
