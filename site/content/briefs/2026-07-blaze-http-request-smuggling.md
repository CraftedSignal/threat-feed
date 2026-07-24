---
title: Multiple HTTP/1.1 Request Smuggling Primitives in Blaze Java Parser
slug: 2026-07-blaze-http-request-smuggling
description: Five independent HTTP/1.1 conformance laxities in Blaze's Java parser cause request-boundary disagreement with a stricter intermediary proxy, enabling front-end ACL/authentication bypass, response-queue poisoning on pooled backend connections, and cache poisoning in affected `http4s-blaze-server` and `blaze-http` components.
date: "2026-07-24T22:28:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - request-smuggling
  - http/1.1
  - java
  - vulnerability
vendors:
  - http4s
products:
  - http4s-blaze-server_2.13
  - blaze-http_2.13
  - blaze-http_3
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: front-end ACL/auth bypass
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Five independent HTTP/1.1 conformance laxities in blaze's hand-written Java parser... cause request-boundary disagreement with a stricter intermediary.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-mhvj-jhpq-885v
---

Five distinct HTTP/1.1 conformance vulnerabilities have been identified in Blaze's hand-written Java parser, specifically within the `http/src/main/java/org/http4s/blaze/http/parser/` component. These laxities in parsing HTTP requests can lead to request-boundary disagreement between a strict intermediary proxy and a vulnerable Blaze server, a classic HTTP request smuggling scenario. The issue affects `http4s-blaze-server_2.13` (versions up to `0.23.17`), `blaze-http_2.13` (versions up to `0.23.17` and from `1.0.0-M1` to `1.0.0-M41`), and `blaze-http_3` (versions up to `0.23.17` and from `1.0.0-M1` to `1.0.0-M41`). These vulnerabilities are reachable via a default `BlazeServerBuilder` configuration. Attackers can leverage this discrepancy to bypass front-end access controls or authentication, poison response queues on pooled backend connections, and corrupt web caches, impacting the integrity and security of web applications. The primary risk lies in deployments using lenient or legacy intermediary proxies that do not strictly conform to RFC HTTP/1.1 parsing rules.

## Attack Chain

1. An attacker crafts a single HTTP/1.1 request containing ambiguous `Content-Length` or `Transfer-Encoding` headers, or other conformance violations, designed to be interpreted differently by an intermediary proxy and the vulnerable Blaze server.
2. The attacker sends this specially crafted, malformed request to the fronting proxy of the target web application.
3. The intermediary proxy, being RFC-strict, processes the initial part of the request, sanitizes or re-serializes it according to its own parsing rules, and forwards what it believes to be a complete, valid request to the backend Blaze server.
4. The vulnerable Blaze server, due to its parsing laxities, interprets the forwarded request differently from the proxy, potentially seeing a second, embedded request where the proxy only saw data for the first.
5. The Blaze server processes this "smuggled" second request, which could contain unauthorized commands or access to restricted resources.
6. This discrepancy leads to various outcomes, such as bypassing authentication, accessing internal resources, poisoning caches, or manipulating subsequent requests in the proxy's queue, ultimately achieving the attacker's objective.

## Impact

The actual exploitability of these vulnerabilities depends heavily on the fronting proxy's behavior, requiring a specific disagreement between the proxy's and the Blaze server's HTTP/1.1 parsers. If the proxy forwards malformed bytes that the Blaze server interprets differently, the consequences include bypassing front-end access control lists (ACLs) or authentication mechanisms, leading to unauthorized access. Attackers can also achieve response-queue poisoning on pooled backend connections, potentially serving malicious content or responses to other users. Additionally, web caches can be poisoned, leading to a denial-of-service or content manipulation. Risk is concentrated on systems using lenient or legacy intermediary proxies that do not strictly enforce HTTP/1.1 RFC compliance.

## Recommendation

* Upgrade `http4s-blaze-server` and `blaze-http` components to patched versions that address these HTTP/1.1 parsing vulnerabilities immediately.
* Deploy affected applications behind an RFC-strict reverse proxy (such as nginx, HAProxy, Envoy, or AWS Application Load Balancer) that explicitly rejects or re-serializes malformed requests at the edge, mitigating the parsing discrepancies before they reach the vulnerable server.
* Monitor web server logs and network traffic for anomalous HTTP request patterns, such as duplicate or malformed `Content-Length` or `Transfer-Encoding` headers, which could indicate request smuggling attempts.
