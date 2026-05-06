---
title: Python-Multipart Denial of Service Vulnerability
slug: 2024-01-python-multipart-dos
description: A denial-of-service vulnerability exists in python-multipart versions prior to 0.0.27 due to unbounded multipart part header parsing, allowing attackers to exhaust CPU resources by sending requests with many repeated headers or a single oversized header value.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - python-multipart
  - web-application
products:
  - python-multipart (< 0.0.27)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-pp6c-gr5w-3c5g
rules:
  - title: Detect Excessive Header Count in Multipart Form Data
    description: Detects a large number of headers within a multipart/form-data request, indicative of a potential DoS attack targeting python-multipart.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
  - title: Detect Large Header Values in Multipart Form Data
    description: Detects excessively large header values within a multipart/form-data request, potentially indicating a DoS attempt targeting python-multipart.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1499.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `python-multipart` library is vulnerable to a denial-of-service (DoS) attack due to unbounded header parsing. This vulnerability affects applications parsing `multipart/form-data` using versions of `python-multipart` prior to 0.0.27. An attacker can exploit this by sending a crafted HTTP request containing either numerous repeated headers without terminating the header block or a single, excessively large header value. This leads to excessive CPU consumption as the server attempts to parse the oversized or numerous headers, potentially causing significant delays or service interruption. ASGI applications such as Starlette and FastAPI, which rely on `python-multipart`, are particularly susceptible.

## Attack Chain

1. An attacker crafts a malicious HTTP POST request with a `multipart/form-data` content type.
2. The malicious request contains either a large number of repeated header lines or a single, oversized header value within a multipart part.
3. The request is sent to a web server running an application that uses `python-multipart` to parse multipart form data.
4. The `MultipartParser` in `python-multipart` attempts to parse the headers.
5. Due to the lack of limits on header count and size in vulnerable versions, the parsing process consumes excessive CPU resources.
6. The server's worker or event loop becomes delayed while processing the malicious request.
7. This delay can lead to a denial of service, as the server is unable to efficiently handle legitimate requests.

## Impact

Successful exploitation of this vulnerability leads to CPU exhaustion on the targeted server, causing delays or interruptions in service. ASGI applications utilizing Starlette, FastAPI, or similar frameworks are at risk. The number of victims depends on the popularity and exposure of the affected applications. The impact includes potential downtime, reduced application performance, and a negative user experience.

## Recommendation

- Upgrade to `python-multipart` version 0.0.27 or later to apply the fix that enforces limits on header count and size.
- If an immediate upgrade is not feasible, implement request body size limits at the server, proxy, or framework level to reduce the potential impact, as recommended in the advisory.
- Monitor web server logs for requests with unusually large header sizes or a high number of headers, using detection rules targeting anomalous header behavior.
