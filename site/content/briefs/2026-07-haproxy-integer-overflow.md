---
title: HAProxy CVE-2021-40346 Integer Overflow Leading to HTTP Request Smuggling and ACL Bypass
slug: 2026-07-haproxy-integer-overflow
description: A critical integer overflow vulnerability, CVE-2021-40346, in HAProxy's `htx_add_header()` function allows unauthenticated attackers to bypass access control rules by crafting HTTP requests with specific header name lengths, leading to HTTP request smuggling and unauthorized access to backend paths, for which a public exploit is available.
date: "2026-07-08T16:05:12Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*
  - cpe:2.3:a:haproxy:haproxy:2.5:dev0:*:*:*:*:*:*
  - cpe:2.3:a:haproxy:haproxy:2.5:dev1:*:*:*:*:*:*
  - cpe:2.3:a:haproxy:haproxy:2.5:dev2:*:*:*:*:*:*
  - cpe:2.3:a:haproxy:haproxy:2.5:dev3:*:*:*:*:*:*
  - cpe:2.3:a:haproxy:haproxy:2.5:dev4:*:*:*:*:*:*
  - cpe:2.3:a:haproxy:haproxy:2.5:dev5:*:*:*:*:*:*
  - cpe:2.3:a:haproxy:haproxy:2.5:dev6:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:33:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*
tags:
  - integer-overflow
  - http-smuggling
  - acl-bypass
  - haproxy
  - webserver
vendors:
  - HAProxy
products:
  - HAProxy (2.0 through 2.0.24)
  - HAProxy (2.2 through 2.2.16)
  - HAProxy (2.3 through 2.3.13)
  - HAProxy (2.4 through 2.4.3)
  - HAProxy (2.5 dev1 through 2.5 dev6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CVE-2021-40346 is an HAProxy Integer Overflow leading to HTTP Request Smuggling.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: 그 결과 설정된 모든 http-request ACL이 우회된다. (As a result, all configured http-request ACLs are bypassed.)
    confidence_band: high
cves:
  - id: CVE-2021-40346
    cvss: 7.5
    epss: 0.57934
references:
  - https://sploitus.com/exploit?id=C6651C75-45C4-5A75-9E0F-77CB87257507
  - https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/
---

A public exploit has been released detailing CVE-2021-40346, an integer overflow vulnerability in HAProxy, an open-source reverse proxy and load balancer. This critical flaw resides in the `htx_add_header()` function, which is responsible for storing HTTP headers internally. The vulnerability allows attackers to perform HTTP Request Smuggling and bypass Access Control List (ACL) rules by manipulating the length of HTTP header names. Specifically, by crafting a header name exactly 270 bytes long, an integer overflow occurs, leading HAProxy to misinterpret a forged `Content-Length: 0` header. This enables the smuggling of a second, hidden request that bypasses HAProxy's initial ACL checks and is delivered to the backend server. The presence of a public Proof-of-Concept (PoC) significantly elevates the risk for unpatched HAProxy installations, particularly versions 2.0 through 2.5 (dev6).

## Attack Chain

1. The attacker crafts an HTTP POST request targeting the HAProxy instance.
2. Within this request, a specially designed header name, such as `Content-Length0` followed by 255 'a' characters (totaling 270 bytes), is included.
3. HAProxy's `htx_add_header()` function attempts to store this header name, which exceeds the capacity of its 8-bit length field.
4. An integer overflow occurs, causing HAProxy to misinterpret the manipulated header as a valid `Content-Length: 0`.
5. Following this forged header, the attacker appends a legitimate `Content-Length` header corresponding to the size of a hidden, malicious HTTP request (e.g., `GET /admin HTTP/1.1`).
6. HAProxy proceeds to read the entire client-provided body, including the hidden request, but its internal logic has been poisoned by the `Content-Length: 0` interpretation.
7. When forwarding to the backend, HAProxy's ACLs, configured to inspect only the initial request line, do not detect the smuggled request.
8. The backend server, having received a `Content-Length: 0` for the initial request, then processes the subsequent hidden data (e.g., `GET /admin`) as a completely new, unauthorized request, effectively bypassing HAProxy's `http-request` ACLs and gaining access to restricted paths.

## Impact

The successful exploitation of CVE-2021-40346 leads to significant security breaches, primarily unauthorized access to restricted backend services and administrative interfaces (e.g., `/admin`). Organizations leveraging HAProxy as a reverse proxy or load balancer with `http-request` based ACLs are at risk. This vulnerability could allow attackers to bypass critical security controls designed to segregate network traffic or protect sensitive application endpoints. Depending on the backend application's functionality, this bypass could lead to further compromise, such as privilege escalation, data exfiltration, or complete system takeover. The availability of a public exploit increases the likelihood of widespread attacks against vulnerable systems.

## Recommendation

* Immediately upgrade HAProxy installations to patched versions: 2.0.25, 2.2.17, 2.3.14, 2.4.4, or newer, to remediate CVE-2021-40346.
* Implement defense-in-depth measures by ensuring backend applications have their own robust authentication and authorization logic, rather than solely relying on proxy ACLs.
