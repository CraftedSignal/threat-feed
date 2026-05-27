---
title: CrowdSec AppSec WAF Bypass via Chunked/HTTP-2 Requests
slug: 2026-05-crowdsec-appsec-waf-bypass
description: CrowdSec AppSec component fails to read the HTTP request body for chunked/HTTP-2 requests, leading to a bypass of WAF rules targeting `REQUEST_BODY`, `BODY_ARGS`, `ARGS_POST`, `JSON`, or `XML`, enabling unauthenticated remote attackers to evade body-inspection pipelines.
date: "2026-05-27T19:59:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - waf-bypass
  - appsec
  - web-application
vendors:
  - CrowdSec
products:
  - CrowdSec AppSec
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Defense Evasion
references:
  - https://github.com/advisories/GHSA-rw47-hm26-6wr7
rules:
  - title: Detect CrowdSec AppSec WAF Bypass via Missing Content-Length
    description: Detects CVE-2026-44982 exploitation — Detects potential CrowdSec AppSec WAF bypass attempts by monitoring for HTTP requests with chunked transfer encoding and 200 OK status codes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - webserver
  - title: Detect CrowdSec AppSec WAF Bypass via HTTP/2 request without Content-Length
    description: Detects CVE-2026-44982 exploitation — Detects potential CrowdSec AppSec WAF bypass attempts by monitoring for HTTP/2 requests lacking a Content-Length header (requires network monitoring).
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The CrowdSec AppSec component, up to version 1.7.7, contains a flaw in its request parsing logic. Specifically, the component fails to correctly read the HTTP request body when the `Content-Length` header is not positive, such as when using `Transfer-Encoding: chunked` in HTTP/1.1 or when the `content-length` header is omitted in HTTP/2 requests. This results in Coraza, the underlying WAF engine, evaluating rules against an empty request body. This issue allows an unauthenticated remote attacker to bypass WAF rules designed to inspect request bodies, potentially leading to successful exploitation of vulnerabilities that would otherwise be blocked. Because bypassed requests do not produce a WAF log entry, defenders lack visibility into these bypass attempts. The vulnerability affects any rule with `zones` containing `BODY_ARGS`, `JSON`, `XML`, `REQUEST_BODY`, or `ARGS_POST`.

## Attack Chain

1. An attacker crafts a malicious HTTP request designed to exploit a vulnerability that requires sending a malicious payload in the request body.
2. The attacker sets the `Transfer-Encoding` header to `chunked` (HTTP/1.1) or omits the `content-length` header entirely (HTTP/2).
3. The malicious request is sent to a server protected by CrowdSec AppSec.
4. CrowdSec AppSec's `NewParsedRequestFromRequest` function incorrectly parses the request body, resulting in an empty body being passed to the WAF engine.
5. The WAF engine evaluates the rules against the empty body, causing all rules targeting `REQUEST_BODY`, `BODY_ARGS`, `ARGS_POST`, `JSON`, or `XML` to fail to match.
6. The malicious request bypasses the WAF's body-inspection pipeline entirely.
7. The bypassed request is forwarded to the backend server.
8. The backend server processes the malicious request, potentially leading to successful exploitation of the underlying vulnerability.

## Impact

Successful exploitation allows attackers to bypass the body-inspection pipeline of CrowdSec AppSec. This bypass can lead to successful exploitation of vulnerabilities that rely on sending malicious data within the request body. Given the wide adoption of CrowdSec for application security, a significant number of systems are potentially affected. The absence of WAF log entries for bypassed requests further complicates detection and incident response. In default CrowdSec deployments using the standard AppSec collections, this bypass will affect a large number of deployed rulesets.

## Recommendation

*   Upgrade to a CrowdSec version greater than 1.7.7 to patch CVE-2026-44982.
*   Deploy the Sigma rule `Detect CrowdSec AppSec WAF Bypass via Missing Content-Length` to detect requests that may be attempting to exploit this bypass by monitoring HTTP status codes combined with `Transfer-Encoding: chunked` headers in web server logs.
*   Deploy the Sigma rule `Detect CrowdSec AppSec WAF Bypass via HTTP/2 request without Content-Length` to detect requests that may be attempting to exploit this bypass by monitoring HTTP/2 traffic and absence of content-length.
*   Examine webserver logs for unexpected "200 OK" responses to requests with large bodies sent using chunked transfer encoding.
