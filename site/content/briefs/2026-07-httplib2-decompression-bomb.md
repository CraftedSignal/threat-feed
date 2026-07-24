---
title: httplib2 Decompression Bomb Denial of Service via Unbounded Gzip/Deflate Handling
slug: 2026-07-httplib2-decompression-bomb
description: A high-severity vulnerability in the `httplib2` Python client library allows a remote attacker to trigger a denial-of-service condition by sending a crafted HTTP response with a small, highly compressed payload that expands excessively upon decompression, causing memory exhaustion or OOM-kill in the client process.
date: "2026-07-24T15:16:49Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:httplib2_project:httplib2:*:*:*:*:*:python:*:*
tags:
  - denial-of-service
  - vulnerability
  - python
  - client-side
vendors:
  - httplib2
  - Google
products:
  - httplib2 (< 0.32.0)
  - google-api-python-client
  - google-auth-httplib2
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A malicious or compromised HTTP server can return a small compressed payload (approximately 150 KB) that expands to an arbitrarily large size in memory (150 MB or more), causing `MemoryError` or OOM-kill in the client process.
    confidence_band: high
cves:
  - id: CVE-2026-59939
    cvss: 7.5
    epss: 0.00358
references:
  - https://github.com/advisories/GHSA-j5g9-f88f-gfj3
---

A critical denial-of-service vulnerability (CVE-2026-59939) has been identified in the `httplib2` Python client library, specifically in versions prior to 0.32.0. This flaw stems from the library's unbounded decompression of HTTP response bodies that are encoded with `gzip` or `deflate`. Attackers can exploit this by controlling an HTTP server or acting as a Man-in-the-Middle (MITM) to send a seemingly small compressed payload (e.g., 150 KB) that, upon automatic decompression by `httplib2`'s `_decompressContent()` function, expands into an arbitrarily large amount of memory (e.g., 150 MB or more). This massive memory consumption leads to `MemoryError` exceptions or an Out-Of-Memory (OOM) kill of the client process, effectively causing a denial of service. Applications using `httplib2.Http().request()` against untrusted or attacker-controlled endpoints are at risk, including downstream dependencies like `google-api-python-client` and `google-auth-httplib2`, which may inadvertently expose their users to this vulnerability.

## Attack Chain

1. An attacker gains control over an HTTP server or establishes a Man-in-the-Middle (MITM) position capable of intercepting and modifying HTTP responses.
2. A client application, using the vulnerable `httplib2` library (versions `< 0.32.0`), initiates an HTTP request to the attacker-controlled or compromised endpoint.
3. The malicious server responds to the client's request, including a `Content-Encoding: gzip` or `Content-Encoding: deflate` header in the HTTP response.
4. The server transmits a small, specially crafted compressed payload (e.g., 150 KB) designed to expand significantly (e.g., 150 MB) upon decompression.
5. The `httplib2` library, specifically the `_decompressContent()` function within `httplib2/__init__.py`, automatically buffers the full compressed body and attempts to decompress it.
6. The `gzip.GzipFile(fileobj=io.BytesIO(new_content)).read()` or `zlib.decompress(content, zlib.MAX_WBITS)` calls proceed to decompress the entire payload into memory without any size limits or sanity checks.
7. This unbounded decompression consumes a disproportionate and ever-growing amount of the client process's memory resources.
8. The excessive memory consumption culminates in a `MemoryError` exception within the client application or an operating system-level Out-Of-Memory (OOM) kill of the client process, causing a denial-of-service condition.

## Impact

This vulnerability carries a high severity, as any application using `httplib2` to make HTTP requests to untrusted servers is susceptible. The attack requires no authentication, specific configuration, or user interaction; the server merely needs to return a specially crafted compressed response. A 150 KB compressed payload can amplify over 1,000 times to 150 MB of decompressed data, making the attack highly effective. Attackers can scale this, where even a 1 MB compressed payload can lead to gigabytes of decompressed data, ensuring an OOM-kill on most systems. Real-world scenarios include web scrapers, API clients connecting to third-party services, webhook handlers, and CI/CD pipelines downloading artifacts. `httplib2` is a widely used Python library, and its dependency in Google's API client libraries (`google-api-python-client`, `google-auth-httplib2`) extends the potential impact to numerous applications relying on Google Cloud APIs, indirectly exposing them to this denial-of-service vector.

## Recommendation

* Upgrade the `httplib2` library to version 0.32.0 or later immediately to address CVE-2026-59939.
* Implement resource limits at the operating system or application level to prevent unbounded memory consumption by client processes, particularly those interacting with untrusted HTTP endpoints.
* Review applications using `httplib2`, `google-api-python-client`, or `google-auth-httplib2` to understand their exposure to untrusted HTTP response sources.
