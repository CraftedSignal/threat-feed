---
title: Rouille HTTP Server Framework Vulnerable to Request Smuggling (CVE-2026-67181)
slug: 2026-07-rouille-http-request-smuggling
description: Rouille HTTP server framework versions 0.3.3 through 3.6.2 are vulnerable to an HTTP request smuggling attack, CVE-2026-67181, allowing remote attackers to desynchronize HTTP message boundaries by exploiting improper header forwarding in the proxy implementation, leading to potential bypassing of security controls or unauthorized access.
date: "2026-07-28T16:23:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - http-request-smuggling
  - server-side
vendors:
  - Rouille
products:
  - Rouille 0.3.3 through 3.6.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Rouille 0.3.3 through 3.6.2 contains an HTTP request smuggling vulnerability that allows remote attackers to desynchronize HTTP message boundaries by exploiting improper header forwarding in the proxy implementation.
    confidence_band: high
cves:
  - id: CVE-2026-67181
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67181
rules:
  - title: Detects CVE-2026-67181 Exploitation - HTTP Request Smuggling Attempt
    description: 'Detects CVE-2026-67181 exploitation - HTTP requests with both ''Content-Length'' and ''Transfer-Encoding: chunked'' headers, which can indicate an HTTP request smuggling attempt targeting Rouille proxy or similar vulnerable web servers.'
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

Rouille, an HTTP server framework for Rust, specifically versions 0.3.3 through 3.6.2, is affected by an HTTP request smuggling vulnerability identified as CVE-2026-67181. This flaw stems from a defect in the framework's proxy implementation, particularly within the `src/proxy.rs` component. Attackers can exploit this by sending a crafted HTTP request where the `Transfer-Encoding` header is improperly forwarded to upstream backends. While the `tiny_http` component de-chunks the request body, the original `Transfer-Encoding` header is sent verbatim to the backend, enabling a "CL.TE" (Content-Length.Transfer-Encoding) desynchronization attack. This allows adversaries to manipulate how the backend perceives the end of an HTTP request, potentially leading to cache poisoning, bypassing security mechanisms, or unauthorized access to internal resources. The vulnerability carries a CVSS v3.1 Base Score of 7.2, indicating a high severity risk.

## Attack Chain

1. An attacker sends a specially crafted HTTP request to a vulnerable Rouille proxy server.
2. The crafted request includes a `Transfer-Encoding: chunked` header and a `Content-Length` header, designed to create ambiguity for the backend.
3. The Rouille proxy, using `tiny_http`, processes and de-chunks the request body received from the client.
4. The proxy then forwards the request to an upstream backend, but critically, it forwards the client's original `Transfer-Encoding: chunked` header unchanged.
5. This creates a desynchronization: the proxy interprets the request body based on the de-chunked content, while the upstream backend attempts to interpret the request based on the forwarded `Transfer-Encoding: chunked` header.
6. By carefully crafting subsequent requests and controlling chunk sizes, the attacker can cause the backend to interpret the end of one request differently than the proxy, allowing parts of the attacker's next request to be prepended to legitimate users' requests.
7. This technique can be used to inject malicious content into cache entries, bypass security appliances, or gain unauthorized access to internal application logic.

## Impact

Successful exploitation of CVE-2026-67181 can lead to various severe consequences for organizations utilizing affected Rouille proxy implementations. The primary impact involves the bypassing of security controls, including web application firewalls (WAFs) and intrusion prevention systems, as the smuggled requests may not be properly inspected. Attackers could also achieve cache poisoning, leading to the serving of malicious or manipulated content to legitimate users. In some scenarios, request smuggling can facilitate unauthorized access to sensitive internal resources or administrative interfaces, potentially escalating to remote code execution (RCE) on the backend servers if further vulnerabilities are chained. While specific victim counts are not available, any organization deploying Rouille as an HTTP proxy in versions 0.3.3 through 3.6.2 is at risk.

## Recommendation

* Patch CVE-2026-67181 on all Rouille HTTP server deployments to version 3.6.3 or newer immediately.
* Deploy the provided Sigma rule to your SIEM to detect suspicious HTTP request headers indicative of request smuggling attempts.
* Monitor `webserver` logs for HTTP requests containing conflicting `Content-Length` and `Transfer-Encoding` headers, as these are common indicators of request smuggling.
