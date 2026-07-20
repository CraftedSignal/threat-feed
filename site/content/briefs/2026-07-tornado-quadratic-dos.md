---
title: Tornado Quadratic DoS via Repeated HTTP Header Coalescing (CVE-2025-67725)
slug: 2026-07-tornado-quadratic-dos
description: A quadratic Denial of Service (DoS) vulnerability exists in Tornado's `HTTPHeaders.add` method due to inefficient string concatenation for repeated header names, which, when processing a maliciously crafted HTTP request with numerous repeated headers, can block the server's single event loop for an extended period, leading to a high severity DoS if `max_header_size` is increased from its default 64KB.
date: "2026-07-20T18:59:34Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:tornadoweb:tornado:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - web-vulnerability
  - python
  - tornado
vendors:
  - Tornado Web Server
products:
  - Tornado (< 6.5.3)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
    evidence: A quadratic Denial of Service (DoS) vulnerability exists in Tornado's `HTTPHeaders.add` method due to inefficient string concatenation for repeated header names.
    confidence_band: high
cves:
  - id: CVE-2025-67725
    cvss: 7.5
    epss: 0.00403
references:
  - https://github.com/advisories/GHSA-c98p-7wgm-6p64
---

A significant Denial of Service (DoS) vulnerability, tracked as CVE-2025-67725, has been identified in the `HTTPHeaders.add` method of the Tornado web server framework, affecting versions prior to 6.5.3. This vulnerability stems from the inefficient handling of repeated HTTP header names. When the same header name is used multiple times in an HTTP request, Tornado's `add` method uses string concatenation to accumulate values. Due to the immutable nature of strings in Python, each concatenation operation creates a new string object, leading to an O(n²) time complexity for processing the headers. Given Tornado's single event loop architecture, a single, specially crafted HTTP request containing an excessive number of repeated header names can consume substantial CPU resources, effectively blocking the event loop and causing a sustained DoS for legitimate users. The severity of this vulnerability is considered high if the `max_header_size` configuration has been increased from its default 64KB, as this allows larger, more impactful malicious requests to be processed.

## Attack Chain

1. An attacker crafts an HTTP request specifically designed with an unusually high number of repeated header names.
2. The attacker sends this maliciously crafted HTTP request to a vulnerable Tornado server instance.
3. The Tornado server receives the HTTP request and begins processing its headers using the `HTTPHeaders.add` method.
4. During header processing, the `add` method attempts to concatenate the values for the repeated header names.
5. Due to Python's string immutability, each concatenation step results in the creation of a new string object, leading to quadratic (O(n²)) time complexity as the number of repeated headers increases.
6. This computationally intensive operation consumes significant CPU resources, causing the server's single event loop to become unresponsive or significantly delayed.
7. The blocking of the event loop prevents the Tornado server from processing other incoming requests, resulting in a Denial of Service for all clients.

## Impact

Successful exploitation of CVE-2025-67725 results in a Denial of Service (DoS) for the affected Tornado web server and its clients. Attackers can render the server inaccessible or severely degrade its performance by sending a single, malformed HTTP request. The impact severity is particularly high if the `max_header_size` configuration setting in the Tornado server has been increased from its default value of 64KB, as this allows for larger malicious requests to be processed, exacerbating the O(n²) overhead. Organizations using vulnerable Tornado versions are at risk of service disruption, lost revenue, and reputational damage.

## Recommendation

* Patch CVE-2025-67725 by upgrading your `pip/tornado` package to version 6.5.3 or later immediately.
* Review your Tornado server configuration to ensure `max_header_size` is set to its default value or an appropriate limit to mitigate the potential impact of large malicious headers.
