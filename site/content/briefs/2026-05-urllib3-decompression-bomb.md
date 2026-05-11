---
title: Urllib3 Decompression Bomb Vulnerability in Streaming API (CVE-2026-44432)
slug: 2026-05-urllib3-decompression-bomb
description: Urllib3 versions before 2.7.0 are vulnerable to excessive resource consumption when using the streaming API to decompress responses, particularly when using the Brotli library or calling HTTPResponse.drain_conn() after partial decompression, leading to high CPU usage and memory allocation, potentially causing a denial-of-service condition (CVE-2026-44432).
date: "2026-05-11T14:53:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - decompression-bomb
  - denial-of-service
  - vulnerability
vendors:
  - Python Packaging Index (PyPI)
products:
  - urllib3 (>= 2.6.0, < 2.7.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-mf9v-mfxr-j63j
  - https://urllib3.readthedocs.io/en/2.7.0/advanced-usage.html#streaming-and-i-o
  - https://pypi.org/project/brotli/
  - https://pypi.org/project/brotlicffi/
  - https://github.com/google/brotli/issues/1396
rules:
  - title: Detect CVE-2026-44432 Exploitation Attempt - HTTP Content-Encoding with Brotli
    description: Detects potential exploitation attempts of CVE-2026-44432 by monitoring for HTTP responses with Brotli content encoding from unusual user agents or connecting to unusual remote IPs, indicating a possible decompression bomb attack.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - webserver
  - title: Detect CVE-2026-44432 - High Memory Usage by Python Processes After HTTP Request
    description: Detects potential exploitation of CVE-2026-44432 by monitoring for unusual spikes in memory usage by Python processes after a network connection, which might indicate a decompression bomb attack triggered by urllib3.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Urllib3's streaming API, designed for efficient handling of large HTTP responses by reading content in chunks, contains a vulnerability in versions prior to 2.7.0. When decompressing content based on the HTTP `Content-Encoding` header (`gzip`, `deflate`, `br`, or `zstd`), the library could decompress the entire response instead of the requested portion in specific cases: when using the Brotli library during the second `HTTPResponse.read(amt=N)` call, or when `HTTPResponse.drain_conn()` was called after the response was partially read and decompressed. This can lead to excessive resource consumption (high CPU usage and memory allocation) on the client side, creating a denial-of-service condition. The vulnerability affects applications streaming compressed responses from untrusted sources. This issue is tracked as CVE-2026-44432.

## Attack Chain

1. An attacker hosts a malicious server with a compressed response (e.g., using Brotli compression) designed to trigger a decompression bomb.
2. A vulnerable application using urllib3 initiates a request to the attacker's server via HTTP.
3. The server responds with a small, highly compressed payload and a `Content-Encoding` header indicating the compression type (e.g., `br`).
4. The application uses urllib3's streaming API to read the response body in chunks with `HTTPResponse.read(amt=N)`.
5. If using Brotli, and the application calls `HTTPResponse.read(amt=N)` a second time, urllib3 attempts to decompress the *entire* response body, regardless of how much data was requested.
6. Alternatively, if the application calls `HTTPResponse.drain_conn()` after partially decompressing the response, urllib3 will attempt to decompress the rest of the payload.
7. The large amount of data resulting from the decompression bomb consumes excessive CPU and memory resources on the client.
8. The client application becomes unresponsive, potentially leading to a denial-of-service condition.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service (DoS) condition on the client side. Applications using affected versions of urllib3 (>= 2.6.0, < 2.7.0) that process compressed data from untrusted sources are vulnerable. The primary damage is excessive CPU and memory consumption, which can render the application unusable. While the exact number of victims is unknown, any application relying on urllib3 for handling compressed HTTP responses is potentially at risk.

## Recommendation

*   Upgrade to urllib3 version 2.7.0 or later to remediate CVE-2026-44432 as noted in the [GHSA-mf9v-mfxr-j63j advisory](https://github.com/advisories/GHSA-mf9v-mfxr-j63j).
*   If upgrading is not immediately possible and the Brotli library is being used, consider switching from the `brotli` package to `brotlicffi` as a temporary workaround, as described in the [GHSA-mf9v-mfxr-j63j advisory](https://github.com/advisories/GHSA-mf9v-mfxr-j63j).
*   Review your code for explicit calls to `HTTPResponse.drain_conn()` and replace them with `HTTPResponse.close()` if connection reuse is not required, as recommended in the [GHSA-mf9v-mfxr-j63j advisory](https://github.com/advisories/GHSA-mf9v-mfxr-j63j).
