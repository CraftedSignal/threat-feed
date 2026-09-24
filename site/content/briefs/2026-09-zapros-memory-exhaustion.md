---
title: Zapros Decompression Bomb Vulnerability in Streaming Decoders
slug: 2026-09-zapros-memory-exhaustion
description: The zapros library fails to enforce memory bounds during response decompression, allowing remote servers to trigger denial-of-service via memory exhaustion (CVE-2026-61652).
date: "2026-09-24T01:58:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:zapros:zapros:*:*:*:*:*:*:*:*
products:
  - zapros (< 0.14.0)
cves:
  - id: CVE-2026-61652
    epss: 0.00263
references:
  - https://github.com/advisories/GHSA-6cp7-3m3c-5x5c
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61652
action_plan:
  priority: elevated
  owners:
    - Application Security
    - Development
  immediate_actions:
    - action: Upgrade zapros dependency to version 0.14.0 or later
      owner: Development
      due: 48h
      evidence: Patches for CVE-2026-61652 are included in version 0.14.0
  mitigation_plan:
    - priority: immediate
      action: Use Response.iter_raw() and implement bounded decompression for unpatched services
      owner: Application Security
      addresses: CVE-2026-61652
      evidence: Workaround documentation in GHSA
---

The zapros library is susceptible to a denial-of-service vulnerability (CVE-2026-61652) caused by improper memory management during the decompression of HTTP response bodies. In affected versions prior to 0.14.0, streaming decoders for gzip, deflate, brotli, and zstd encodings ignore the requested chunk size provided by the caller. 

An attacker controlling a malicious server can transmit a specially crafted, highly compressed payload (a decompression bomb) that expands to a significantly larger size upon decoding. Because the library fails to limit the output of each decompression step to the requested chunk size, a single chunk can force the client application to allocate excessive memory, leading to process instability or termination. This is particularly critical for applications that process data from untrusted sources, as the memory exhaustion is triggered automatically upon reading the response stream.

## Impact

The vulnerability results in a denial-of-service condition due to heap memory exhaustion. Applications using zapros to fetch data from untrusted or compromised endpoints are at risk of crashing when handling malicious compressed payloads. The impact is significant for services that rely on zapros for high-frequency or long-running data ingestion, as a single malicious response can terminate the service process.

## Recommendation

Prioritized actions for development and security operations:

* Update the zapros library dependency to version 0.14.0 or later to ensure that decompression output is bounded to the requested chunk size.
* For applications that cannot be immediately patched, transition to reading responses using Response.iter_raw() and implement a manual, bounded decompression logic that aborts when a defined size limit is exceeded.
* Disable response compression in client requests where possible by sending 'Accept-Encoding: identity' to prevent the library's decoders from processing potentially malicious payloads.
* Avoid automated decoding of response bodies received from untrusted or third-party servers.
