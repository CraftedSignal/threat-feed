---
title: Plug Multipart Header Parsing Denial-of-Service Vulnerability (CVE-2026-8468)
slug: 2026-05-plug-multipart-dos
description: Plug versions 1.4.0 to 1.19.1 are vulnerable to denial-of-service (CVE-2026-8468) due to unbounded buffer accumulation in multipart header parsing, allowing an unauthenticated attacker to exhaust server memory by sending a crafted multipart/form-data request.
date: "2026-05-20T15:36:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - multipart
  - web-application
vendors:
  - Erlang
products:
  - plug
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Defense Evasion
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-8468
    epss: 0.00204
references:
  - https://github.com/advisories/GHSA-468c-vq7p-gh64
  - https://github.com/elixir-plug/plug/commit/c52b2f32c90bccd718202bafccb5f95594e30183
  - https://github.com/elixir-plug/plug/commit/d878b42efea9f12b243dc3e362a2ed048a798203
rules:
  - title: Detect Suspicious Multipart Form Request
    description: Detects CVE-2026-8468 attempt — Identifies HTTP requests with multipart/form-data content type and excessively long header fields, potentially indicating a denial-of-service attack.
    platform: sigma
    severity: medium
    tactics:
      - dos
    techniques:
      - T1499
    data_sources:
      - webserver
  - title: Detect POST Without Content Length
    description: Detects a POST request without content length. This is often used for DOS attacks.
    platform: sigma
    severity: low
    tactics:
      - dos
    techniques:
      - T1499
    data_sources:
      - webserver
rules_count: 2
---

Plug, a popular web application library for Elixir, is susceptible to a denial-of-service vulnerability (CVE-2026-8468) within its multipart header parsing functionality. The vulnerability resides in the `Plug.Conn.read_part_headers/2` function, which fails to enforce limits on the size of the accumulated buffer when parsing multipart/form-data requests. This flaw allows an unauthenticated attacker to send specially crafted HTTP requests containing excessively large multipart headers, leading to uncontrolled memory allocation on the server. By repeatedly sending such requests, an attacker can exhaust available memory resources, ultimately causing the server to crash or become unresponsive, resulting in a denial of service. Specifically, versions >= 1.4.0, < 1.15.4, versions >= 1.16.0, < 1.16.3, versions >= 1.17.0, < 1.17.1, versions >= 1.18.0, < 1.18.2 and versions >= 1.19.0, < 1.19.2 are affected.

## Attack Chain

1. The attacker identifies a Plug-based web application that utilizes `Plug.Parsers` with the `:multipart` parser or calls `Plug.Conn.read_part_headers/2` directly.
2. The attacker crafts a malicious HTTP request with the `Content-Type` header set to `multipart/form-data`.
3. Within the multipart data, the attacker constructs a part header with an excessively large size, exceeding expected limits. The attacker omits a closing boundary to continue the uncontrolled header accumulation.
4. The attacker sends the crafted HTTP request to the vulnerable endpoint of the Plug application.
5. The `Plug.Conn.read_part_headers/2` function processes the request and begins accumulating the multipart header data without proper length validation.
6. The function continuously allocates memory to store the expanding header buffer, consuming available server resources.
7. The attacker repeats the process by sending multiple malicious requests, accelerating memory exhaustion.
8. Eventually, the server runs out of memory, causing the Plug application to crash or become unresponsive, resulting in a denial of service.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition, rendering the affected Plug-based web application unavailable to legitimate users. The impact could range from temporary service disruptions to prolonged outages, depending on the severity of the memory exhaustion and the system's recovery capabilities. The number of victims depends on the popularity and criticality of the affected applications. There is no evidence of widespread exploitation at this time.

## Recommendation

*   Upgrade to Plug version 1.15.4, 1.16.3, 1.17.1, 1.18.2, 1.19.2, or later, which includes the patch for CVE-2026-8468 (see References).
*   Deploy the Sigma rule `Detect Suspicious Multipart Form Request` to identify and block requests with abnormally large multipart headers.
*   Monitor web server logs for a high volume of `multipart/form-data` requests with unusually large header sizes.
