---
title: Netty HTTP/2 Decompressor Direct Memory Leak
slug: 2026-07-netty-memory-leak
description: A vulnerability in Netty's HTTP/2 decompressor allows an unauthenticated attacker to trigger an uncontrolled memory leak leading to a JVM OutOfMemoryError via crafted HTTP/2 DATA frames.
date: "2026-07-31T19:29:49Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:netty:netty:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - memory-leak
  - netty
  - cve-2026-56819
vendors:
  - Netty
products:
  - netty-codec-http2 (4.1.x)
  - netty-codec-http2 (4.2.x)
cves:
  - id: CVE-2026-56819
    cvss: 7.5
    epss: 0.00365
references:
  - https://github.com/advisories/GHSA-93wv-jw9v-4972
---

Netty versions 4.1.x and 4.2.x are vulnerable to a direct memory leak (CWE-401) when the `DelegatingDecompressorFrameListener` is used for HTTP/2 content decompression. The issue occurs within the `Http2Decompressor.decompress()` method, where an incoming `ByteBuf` is retained before checking the status of the decompressor channel. 

If the decompressor channel has been closed or cleaned up, the `writeInbound()` call fails with a `ClosedChannelException`. Because the code does not perform a rollback of the reference count increment in this error path, the buffer is never released. An attacker can exploit this by sending `DATA` frames for streams that have already reached an `END_STREAM` state or been cleaned up. Sustained exploitation causes the accumulation of unreferenced direct memory objects, leading to an `OutOfMemoryError` (DoS) and application crash. This affects users of `netty-codec-http2` across the 4.1.x and 4.2.x branches.

## Attack Chain

1. Attacker establishes a legitimate, long-lived HTTP/2 connection to a vulnerable server.
2. Attacker initiates a stream and sends data frames to trigger standard decompressor processing.
3. Attacker sends a final frame to signal `END_STREAM`, forcing the server to trigger `onStreamRemoved` and `Http2Decompressor.cleanup()`.
4. Attacker continues to send additional `DATA` frames associated with the now-closed stream.
5. The `DelegatingDecompressorFrameListener` calls `decompressor.writeInbound(data.retain())`.
6. The `EmbeddedChannel.ensureOpen()` method throws a `ClosedChannelException` because the channel is closed.
7. The catch block in `Http2Decompressor` fails to call `data.release()` on the leaked buffer.
8. The direct memory is leaked; repetition of this process exhausts the heap and crashes the service.

## Impact

The vulnerability allows an unauthenticated remote attacker to cause a denial-of-service condition by crashing the JVM. This affects any application utilizing the `DelegatingDecompressorFrameListener` component within an HTTP/2 pipeline, which is a common pattern for high-performance network services. Repeated exploitation leads to direct memory exhaustion, which is particularly critical in containerized environments with memory limits where the OOM error occurs rapidly.

## Recommendation

1. Upgrade to the latest patched version of `netty-codec-http2` provided by the Netty Project to remediate CVE-2026-56819.
2. Implement an application-level rate limit on HTTP/2 streams to detect and disconnect peers that continue to send data after a stream has been closed, which serves as a mitigation until patching can occur.
3. If patching is not immediately feasible, inspect the `DelegatingDecompressorFrameListener` implementation and manually apply the rollback logic as documented in the GHSA-93wv-jw9v-4972 advisory to ensure the reference count is decremented on failure.
