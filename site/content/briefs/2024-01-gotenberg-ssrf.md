---
title: Gotenberg Unauthenticated SSRF Vulnerability
slug: 2024-01-gotenberg-ssrf
description: Gotenberg is vulnerable to Server-Side Request Forgery (SSRF) due to bypassable default deny-lists in the `downloadFrom` and `webhook` features, where case-sensitive regex matching allows attackers to use IPv6 loopback URLs to bypass the deny-list and access internal HTTP services.
date: "2026-05-07T01:15:19Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ssrf
  - vulnerability
  - gotenberg
vendors:
  - Gotenberg
products:
  - Gotenberg
references:
  - https://github.com/advisories/GHSA-4vmc-gm8v-m35h
iocs:
  - type: url
    value: http://[::ffff:127.0.0.1]:18081/page_1.pdf
  - type: url
    value: http://[::ffff:127.0.0.1]:18082/upload
  - type: url
    value: http://[::ffff:127.0.0.1]:18082/events
ioc_counts:
  url: 3
rules:
  - title: Detect Gotenberg SSRF via IPv6 Loopback Bypass - downloadFrom
    description: Detects SSRF attempts in Gotenberg's downloadFrom feature by identifying requests with IPv6 loopback addresses in the URL.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
  - title: Detect Gotenberg SSRF via IPv6 Loopback Bypass - webhook
    description: Detects SSRF attempts in Gotenberg's webhook feature by identifying requests with IPv6 loopback addresses in the Gotenberg-Webhook-Url header.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Gotenberg, a Docker-based solution for converting HTML, Markdown, and Office documents to PDF, contains an unauthenticated SSRF vulnerability affecting its `downloadFrom` and `webhook` features. The vulnerability stems from a bypassable default deny-list that is intended to prevent the service from making outbound requests to internal-only targets. Due to case-sensitive regex matching, an attacker can supply URLs encoded with IPv6 loopback addresses, such as `http://[::ffff:127.0.0.1]:...`, to circumvent the deny-list. This allows an external attacker to force the Gotenberg server to make outbound requests to internal-only resources, potentially exposing sensitive information or services. The issue affects versions of Gotenberg prior to the fix, and defenders should implement mitigations to prevent unauthorized access to internal resources.

## Attack Chain

1.  An attacker identifies a Gotenberg instance with the vulnerable `downloadFrom` or `webhook` features enabled.
2.  The attacker crafts a malicious URL containing an IPv6 loopback address (e.g., `http://[::ffff:127.0.0.1]:18081/page_1.pdf`) to bypass the case-sensitive deny-list.
3.  For the `downloadFrom` feature, the attacker sends a POST request to `/forms/pdfengines/metadata/read` with the crafted URL in the `downloadFrom` parameter.
4.  For the `webhook` feature, the attacker sends a POST request to `/forms/pdfengines/flatten` with the crafted URL in the `Gotenberg-Webhook-Url` or `Gotenberg-Webhook-Events-Url` header.
5.  Gotenberg's filtering logic, due to its case sensitivity, fails to block the request because of the IPv6 loopback formatting.
6.  Gotenberg makes an outbound GET request (for `downloadFrom`) or POST request (for `webhook`) to the attacker-specified internal resource.
7.  The internal resource processes the request and returns data to the Gotenberg server.
8.  The attacker gains access to the data from the internal resource via the Gotenberg server, potentially leading to information disclosure or further exploitation.

## Impact

Successful exploitation of this SSRF vulnerability allows unauthenticated attackers to bypass intended restrictions and force the Gotenberg server to interact with internal resources. This can lead to the exposure of sensitive information residing on internal services, potentially including configuration files, internal APIs, or other confidential data. The impact could include unauthorized access to sensitive systems, data exfiltration, or the ability to pivot further into the internal network.

## Recommendation

*   Inspect webserver logs for HTTP requests containing URLs with IPv6 loopback addresses such as `http://[::ffff:127.0.0.1]` in the request URI or headers, specifically targeting the `/forms/pdfengines/metadata/read` and `/forms/pdfengines/flatten` endpoints.
*   Deploy the Sigma rule provided in this brief to detect SSRF attempts using IPv6 loopback bypasses.
*   Block the identified IOCs (URLs containing IPv6 loopback addresses) at network perimeters to prevent initial exploitation attempts.
