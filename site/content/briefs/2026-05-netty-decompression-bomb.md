---
title: Netty HttpContentDecompressor Brotli/Zstd/Snappy Decompression Bomb Vulnerability
slug: 2026-05-netty-decompression-bomb
description: Netty's HttpContentDecompressor and DelegatingDecompressorFrameListener are vulnerable to a decompression bomb denial-of-service attack because the maxAllocation parameter is not enforced when Content-Encoding is set to br (Brotli), zstd, or snappy, allowing attackers to bypass decompression limits and cause unbounded memory allocation.
date: "2026-05-07T00:46:35Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - decompression-bomb
  - denial-of-service
  - netty
  - http
vendors:
  - Netty
products:
  - netty-codec-http (>= 4.2.0.Alpha1, <= 4.2.12.Final)
  - netty-codec-http2 (>= 4.2.0.Alpha1, <= 4.2.12.Final)
  - netty-codec-http (<= 4.1.132.Final)
  - netty-codec-http2 (<= 4.1.132.Final)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-f6hv-jmp6-3vwv
rules:
  - title: Detect HTTP Request with Brotli Content-Encoding
    description: Detects HTTP requests with Brotli content encoding, which might indicate attempts to exploit the decompression vulnerability.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1499
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP Request with Zstd Content-Encoding
    description: Detects HTTP requests with Zstd content encoding, which might indicate attempts to exploit the decompression vulnerability.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1499
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP Request with Snappy Content-Encoding
    description: Detects HTTP requests with Snappy content encoding, which might indicate attempts to exploit the decompression vulnerability.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1499
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 3
---

The Netty framework is susceptible to a decompression bomb vulnerability in its `HttpContentDecompressor` and `DelegatingDecompressorFrameListener` components. This flaw, present in versions up to 4.2.12.Final and 4.1.132.Final, arises because the `maxAllocation` parameter, intended to limit decompression buffer size, is ignored when content is encoded using Brotli (`br`), Zstandard (`zstd`), or Snappy. An attacker can exploit this by sending a specially crafted compressed payload with a `Content-Encoding` header set to one of the affected algorithms. This circumvents the configured memory limits, leading to excessive memory allocation and ultimately causing an out-of-memory denial-of-service (DoS) condition on the server. The vulnerability affects both HTTP/1.1 and HTTP/2 connections.

## Attack Chain

1. The attacker identifies a Netty-based HTTP server that uses `HttpContentDecompressor` or `DelegatingDecompressorFrameListener` with a configured `maxAllocation` value.
2. The attacker crafts a malicious compressed payload designed to expand dramatically upon decompression (a "decompression bomb"). For example, a small compressed file expands to gigabytes of zeros.
3. The attacker sets the `Content-Encoding` HTTP header to `br`, `zstd`, or `snappy`.
4. The attacker sends an HTTP POST request to the vulnerable server, including the malicious compressed payload in the request body.
5. The server receives the request and `HttpContentDecompressor` or `DelegatingDecompressorFrameListener` processes the request, detects the `Content-Encoding`, and attempts to decompress it using the corresponding decoder (`BrotliDecoder`, `ZstdDecoder`, or `SnappyFrameDecoder`).
6. Because the `maxAllocation` is not enforced for these decoders, decompression proceeds without memory limits.
7. The decoder allocates memory to store the decompressed data, which rapidly consumes available memory.
8. The server runs out of memory, causing a denial-of-service condition for legitimate users.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition on the targeted Netty server. This can disrupt services, cause downtime, and impact legitimate users. Organizations using affected versions of Netty are vulnerable to this attack. Developers may have a false sense of security, believing that `maxAllocation` protects them from all decompression bombs, but are unknowingly exposed when using brotli, zstd, or snappy encodings. A trivial header modification bypasses the intended protection.

## Recommendation

*   Upgrade to a patched version of Netty that addresses CVE-2026-42587.
*   Apply the recommended fix by passing `maxAllocation` to all decoder constructors, including `BrotliDecoder`, `SnappyFrameDecoder`, and `ZstdDecoder`, as outlined in the advisory.
*   For `BrotliDecoder` and `SnappyFrameDecoder`, implement `maxAllocation` parameter with the same semantics as `ZlibDecoder.prepareDecompressBuffer()`.
*   For `ZstdDecoder`, ensure that when `maxAllocation` is set, total output across all buffers is bounded.
*   Implement a network-level rule to limit the size of compressed requests based on `Content-Encoding` header and request size to mitigate potential decompression attacks even if the application is vulnerable.
