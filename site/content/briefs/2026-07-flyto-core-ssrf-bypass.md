---
title: flyto-core SSRF Bypass via IPv6 Transition Addresses (CWE-918)
slug: 2026-07-flyto-core-ssrf-bypass
description: An authenticated workflow author can bypass `flyto-core`'s Server-Side Request Forgery (SSRF) protection by crafting URLs with IPv6 transition addresses that embed private IPv4s, allowing for data exfiltration from internal services like cloud instance metadata.
date: "2026-07-06T17:36:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - vulnerability
  - python
  - defense-evasion
vendors:
  - flytohub
products:
  - flyto-core
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: The guard that exists specifically to keep workflow-authored URLs away from internal/metadata endpoints is bypassable
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1538
    technique_name: Cloud APIs
    evidence: Cloud instance-metadata service (... exposing IAM credentials / instance identity).
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The response body is returned, so this is a read SSRF (data exfiltration from internal services)
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-794r-5rp2-fpg8
iocs:
  - type: url
    value: http://[64:ff9b::a9fe:a9fe]/latest/meta-data/
  - type: domain
    value: metadata.google.internal
  - type: ip
    value: 169.254.169.254
ioc_counts:
  domain: 1
  ip: 1
  url: 1
---

The `flyto-core` application, developed by flytohub, contains a critical Server-Side Request Forgery (SSRF) vulnerability, identified as CWE-918, in its `validate_url_ssrf` function, specifically within the `is_private_ip` helper in `src/core/utils.py`. This vulnerability, published on 2026-07-06, allows an authenticated workflow author to bypass the intended SSRF protection by utilizing IPv6 transition addresses. The application's guard, designed to block access to private and cloud metadata services, fails to correctly identify private IP addresses embedded within IPv4-mapped, 6to4, or NAT64 IPv6 formats. This oversight enables attackers to craft URLs using these unblocked IPv6 forms to access internal resources like cloud instance metadata services (e.g., `169.254.169.254`) or internal loopback services. The response body from these internal services is then returned to the attacker, resulting in a read SSRF that can lead to the exfiltration of sensitive information, such as IAM credentials. This bypass directly undermines the project's documented security controls.

## Attack Chain

1.  A workflow author, possessing valid authentication credentials for `flyto-core`'s Execution API (`POST /v1/execute`), prepares to execute a module.
2.  The attacker crafts a malicious URL containing an IPv6 transition-form host, such as `http://[::ffff:127.0.0.1]:8080/` for loopback access or `http://[64:ff9b::a9fe:a9fe]/latest/meta-data/` for cloud instance metadata.
3.  The attacker sends a `POST` request to `http://127.0.0.1:8333/v1/execute` with a JSON payload including `{"module_id":"http.get", "params":{"url":"[malicious_url]"}}`.
4.  The `flyto-core` application invokes `validate_url_ssrf`, which calls `is_private_ip()` on the IPv6 transition address. Due to the vulnerability, `is_private_ip()` incorrectly returns `False`.
5.  The `http.get` atomic module proceeds to initiate an outbound HTTP GET request using `aiohttp` to the internal destination specified by the crafted URL.
6.  The internal service (e.g., cloud metadata service or a local web server) processes the request and returns its sensitive response body.
7.  `flyto-core` receives the internal service's response and, as part of the `http.get` module's functionality, returns the full response body to the attacker in the `/v1/execute` API response.
8.  The attacker successfully exfiltrates sensitive data, such as IAM credentials or internal service information, via a read Server-Side Request Forgery.

## Impact

The vulnerability allows an authenticated workflow author to bypass `flyto-core`'s security controls and perform read Server-Side Request Forgery (SSRF). This directly enables data exfiltration from internal services that are typically isolated from external access. Specifically, attackers can access cloud instance metadata services (e.g., `169.254.169.254`) to steal highly sensitive IAM credentials and instance identity information. Additionally, the bypass permits access to internal loopback and RFC 1918 services, potentially exposing other sensitive internal applications or data. The success of this attack directly undermines the intended security model of `flyto-core`, which explicitly documents these checks as critical security controls. While the source does not provide victim numbers, any organization using `flyto-core` is susceptible, especially those deployed in cloud environments.

## Recommendation

*   Immediately apply the patch provided by flytohub, which modifies `src/core/utils.py` to correctly identify and block private IP addresses embedded within IPv6 transition forms, as demonstrated in the "Suggested fix" section of this brief.
*   Review all `flyto-core` deployments, especially those in cloud environments, to ensure proper network segmentation and defense-in-depth measures limit the impact of potential SSRF vulnerabilities.
*   Monitor network egress logs for connections originating from `flyto-core` instances to unusual or internal-only IPv6 addresses, particularly those resembling the IPv4-mapped `::ffff:169.254.169.254`, NAT64 `64:ff9b::/96`, or 6to4 `2002::/16` prefixes.
*   Ensure that cloud metadata services and other sensitive internal endpoints are configured with least privilege access and minimal exposed information, assuming they might eventually be accessed by an SSRF attack.
