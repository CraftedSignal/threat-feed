---
title: Fastify Proxy Header Stripping Vulnerability
slug: 2026-04-fastify-header-strip
description: The `@fastify/reply-from` and `@fastify/http-proxy` libraries process the client's `Connection` header after adding headers, allowing attackers to strip proxy-added headers via the `Connection` header, leading to potential bypass of security controls.
date: "2026-04-16T01:02:59Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - fastify
  - header stripping
  - proxy vulnerability
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Relationships
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1553
    technique_name: Subvert Trust Relationships
references:
  - https://github.com/advisories/GHSA-gwhp-pf74-vj37
rules:
  - title: Detect Fastify Proxy Header Stripping Attempt
    description: Detects requests with a 'Connection' header attempting to strip common proxy-added headers.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
  - title: 'Detect Fastify Proxy Header Stripping - Connection: close'
    description: Detects requests with a 'Connection' header set to 'close', which, while legitimate, could be used in conjunction with other header manipulation techniques.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `@fastify/reply-from` and `@fastify/http-proxy` libraries are vulnerable to a header stripping attack. This vulnerability stems from the incorrect processing order of the `Connection` header. The client's `Connection` header is processed *after* the proxy has added custom headers via the `rewriteRequestHeaders` function. This allows an attacker to retroactively remove headers added by the proxy by simply listing them in the `Connection` header. This affects any application leveraging these plugins where custom headers are injected for routing, access control, or other security purposes. All versions of both `@fastify/reply-from` and `@fastify/http-proxy` are affected. The vulnerability can be exploited without any special configuration. This undermines the intended function of a proxy as a trusted intermediary.

## Attack Chain

1. A client crafts a request containing a `Connection` header.
2. The client sends the crafted request to a Fastify proxy server using `@fastify/reply-from` or `@fastify/http-proxy`.
3. The proxy receives the request and copies all client headers, including the `Connection` header.
4. The proxy, using `rewriteRequestHeaders`, adds custom headers (e.g., `x-forwarded-by`) to the request.
5. The proxy's transport handler processes the `Connection` header from the client.
6. Headers listed in the client's `Connection` header, including proxy-added headers, are stripped from the upstream request.
7. The modified request, with stripped headers, is forwarded to the upstream server.
8. The upstream server receives the request with missing headers, potentially bypassing security checks.

## Impact

Successful exploitation allows attackers to bypass security controls implemented by the proxy. This includes bypassing proxy identification, circumventing access control mechanisms, and removing arbitrary headers. For example, an attacker can strip headers like `x-forwarded-by` to avoid detection, or remove authentication headers like `authorization` or custom access control headers like `x-internal-auth` to gain unauthorized access to resources. The number of victims depends on the prevalence of vulnerable Fastify deployments.

## Recommendation

*   Upgrade to patched versions of `@fastify/reply-from` and `@fastify/http-proxy` when available.
*   As a workaround, avoid using `rewriteRequestHeaders` to inject security-critical headers into requests.
*   Implement input validation to sanitize or reject requests containing a `Connection` header that attempts to remove security-sensitive headers.
*   Monitor web server logs for requests containing `Connection` headers listing custom or security-related headers as a sign of potential exploitation (see Sigma rule below).
