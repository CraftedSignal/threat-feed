---
title: Tornado Web Server Quadratic DoS Vulnerability (CVE-2025-67726)
slug: 2026-07-tornado-quadratic-dos
description: A high-severity quadratic time complexity vulnerability (CVE-2025-67726) in Tornado's `_parseparam` function allows an attacker to cause a Denial of Service (DoS) by sending crafted `multipart/form-data` requests with malicious parameters in the `Content-Disposition` header to vulnerable Tornado web servers versions prior to 6.5.3.
date: "2026-07-20T18:58:57Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:tornadoweb:tornado:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - web-application
  - python
vendors:
  - Tornado Project
products:
  - Tornado (< 6.5.3)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: a single malicious request can cause the entire server to become unresponsive for an extended period, leading to a Denial of Service (DoS).
    confidence_band: high
cves:
  - id: CVE-2025-67726
    cvss: 7.5
    epss: 0.00378
references:
  - https://github.com/advisories/GHSA-jhmp-mqwm-3gq8
---

A high-severity Denial of Service (DoS) vulnerability, tracked as CVE-2025-67726, exists in the Tornado web framework, affecting versions prior to 6.5.3. This vulnerability stems from an inefficient algorithm within the `_parseparam` function located in `httputil.py`, which is responsible for parsing HTTP header values such as those found in `multipart/form-data` requests. Specifically, the function repeatedly calls `string.count()` within a nested loop when processing quoted semicolons (e.g., `param=";"`). An attacker can exploit this by sending a crafted HTTP request containing a large number of such parameters in a `Content-Disposition` header. This triggers a quadratic increase (O(n²)) in server CPU usage during parsing. Due to Tornado's single event loop architecture, a single malicious request can render the entire server unresponsive for an extended period, leading to a complete DoS.

## Attack Chain

1. Attacker identifies a web server running an unpatched Tornado instance, specifically versions prior to 6.5.3.
2. Attacker crafts a malicious HTTP request intended to exploit the `_parseparam` function.
3. The request includes a `Content-Disposition` header, typically found within `multipart/form-data` requests.
4. Within this `Content-Disposition` header, the attacker embeds a large quantity of specially crafted parameters.
5. These parameters are designed to leverage quoted semicolons (e.g., `filename="data;a=b;c=d;;"`), which trigger the inefficient parsing logic.
6. Upon receiving the malicious request, the vulnerable Tornado server initiates parsing of the `Content-Disposition` header using the `_parseparam` function in `httputil.py`.
7. The quadratic time complexity (O(n²)) of `_parseparam` when processing these crafted parameters consumes excessive CPU resources.
8. Due to Tornado's single event loop architecture, the server becomes unresponsive to legitimate requests, resulting in a Denial of Service.

## Impact

Successful exploitation of CVE-2025-67726 leads to a complete Denial of Service for the affected Tornado web server. The server's CPU usage increases quadratically, rendering it unresponsive and unable to process legitimate requests. This can cause significant disruption to services, downtime, and potential data loss for applications reliant on the vulnerable Tornado instance. The impact is primarily on the availability of the web service.

## Recommendation

* Patch CVE-2025-67726 immediately by upgrading all Tornado installations to version 6.5.3 or later.
* Implement a Web Application Firewall (WAF) or intrusion prevention system (IPS) capable of inspecting and blocking HTTP requests with abnormally large or malformed `Content-Disposition` headers containing repeated quoted semicolons, to mitigate attacks against CVE-2025-67726 before patching is complete.
