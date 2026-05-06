---
title: Snappier SnappyStream Decompression Infinite Loop Vulnerability
slug: 2026-05-snappier-dos
description: Snappier versions 1.3.0 and earlier are vulnerable to a denial-of-service condition where a malformed Snappy stream input to `SnappyStream` decompression causes an infinite loop, consuming a thread until the process is terminated.
date: "2026-05-06T20:53:23Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - compression
  - infinite-loop
vendors:
  - NuGet
products:
  - Snappier (<= 1.3.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-pggp-6c3x-2xmx
rules:
  - title: Detect High CPU Usage by Snappier Application
    description: Detects processes using the Snappier library that are consuming excessive CPU, potentially indicating an infinite loop due to malformed Snappy stream decompression.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Snappier Decompression from Suspicious Source
    description: Detects Snappier decompression processes initiated from unusual or temporary locations, potentially indicating malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Snappier library, specifically the `SnappyStream` class, is susceptible to a denial-of-service vulnerability when decompressing malformed Snappy streams in framed format. An attacker who can control the input to the `SnappyStream` decompression process can trigger an infinite loop, leading to excessive CPU consumption and thread exhaustion. This issue affects applications using Snappier version 1.3.0 and earlier. The vulnerability stems from an unhandled condition in the decompression logic, causing the `SnappyStreamDecompressor.Decompress` method to repeatedly call `Crc32CAlgorithm.Append` without termination. Standard exception handling mechanisms (try/catch blocks) are ineffective in preventing the hang, making it difficult to mitigate without terminating the affected process.

## Attack Chain

1. An attacker crafts a malformed Snappy compressed data stream (as small as 15 bytes).
2. The attacker sends this malformed stream to a service or application using the Snappier library for decompression.
3. The application instantiates a `SnappyStream` object with `CompressionMode.Decompress` to handle the incoming data stream.
4. The application calls `CopyTo()` or a similar method on the `SnappyStream` to decompress the data.
5. The `SnappyStreamDecompressor.Decompress` method is invoked internally.
6. Due to the malformed input, an infinite loop occurs within `SnappyStreamDecompressor.Decompress` involving repeated calls to `Crc32CAlgorithm.Append`.
7. A single CPU core is consumed at 100% by the affected thread.
8. The application hangs indefinitely, requiring termination to recover.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition. An attacker can remotely trigger the infinite loop by sending malicious data to any application that utilizes the vulnerable `Snappier.SnappyStream` for decompression. This can lead to resource exhaustion, application unavailability, and potentially impact other services relying on the same system. Since the `try/catch` doesn't work, the service will remain inoperable until manually restarted.

## Recommendation

*   Upgrade to a patched version of the Snappier library that addresses CVE-2026-44302.
*   Implement input validation and sanitization on data streams prior to decompression using `Snappier.SnappyStream`.
*   Monitor CPU usage for processes utilizing the Snappier library. Deploy the process monitoring rule below to detect potential exploitation attempts based on high CPU usage.
