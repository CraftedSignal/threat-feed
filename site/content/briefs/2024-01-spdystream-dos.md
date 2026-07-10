---
title: spdystream SPDY/3 Frame Parser Denial of Service
slug: 2024-01-spdystream-dos
description: The SPDY/3 frame parser in spdystream before v0.5.1 improperly validates attacker-controlled counts and lengths, allowing a remote attacker to trigger excessive memory allocation and cause a denial-of-service condition.
date: "2024-01-09T16:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - spdy
  - denial-of-service
  - memory-allocation
  - spdystream
vendors:
  - Moby
products:
  - spdystream
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://github.com/advisories/GHSA-pc3f-x583-g7j2
rules:
  - title: Detect SPDY SETTINGS Frame with Large numSettings
    description: Detects SPDY SETTINGS frames with a numSettings value that exceeds the expected frame length, indicating a potential denial-of-service attempt.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - zeek
  - title: Detect SPDY Connection Reset Due to Protocol Error
    description: Detects SPDY connections being reset due to protocol errors, which may indicate exploitation of SPDY parsing vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - zeek
rules_count: 2
---

The `spdystream` library, specifically versions 0.5.0 and earlier, contains a vulnerability in its SPDY/3 frame parser. This vulnerability allows a remote attacker to cause a denial-of-service (DoS) by sending specially crafted SPDY frames to a service that utilizes `spdystream`. The vulnerability stems from the lack of validation of attacker-controlled counts and lengths before memory allocation, leading to excessive memory usage and, ultimately, an out-of-memory crash. A single crafted SPDY control frame is sufficient to exhaust the process's memory. This issue was resolved in version 0.5.1. The affected package is `github.com/moby/spdystream`.

## Attack Chain

1. The attacker establishes a SPDY connection with a service using the vulnerable `spdystream` library.
2. The attacker crafts a SPDY SETTINGS frame with a malicious `numSettings` value exceeding the frame length.
3. The vulnerable `spdystream` library receives the crafted SETTINGS frame.
4. The `SETTINGS` frame reader allocates memory based on the attacker-controlled `numSettings` without proper validation.
5. Alternatively, the attacker sends a zlib-compressed SPDY header block.
6. The vulnerable `spdystream` library decompresses the header block, resulting in attacker-controlled bytes interpreted as `numHeaders`.
7. The `parseHeaderValueBlock` function allocates an `http.Header` map of the specified `numHeaders` size without any upper bound, exhausting available memory.
8. The process crashes due to an out-of-memory error, causing a denial of service.

## Impact

Any program accepting SPDY connections through the vulnerable `spdystream` library is susceptible. A successful attack allows a remote peer to crash the process with a single, specially crafted SPDY control frame. This leads to a denial-of-service condition, potentially impacting the availability of critical services. While the exact number of victims and sectors targeted remains unknown, the widespread use of SPDY and related protocols makes this a significant concern.

## Recommendation

*   Upgrade the `github.com/moby/spdystream` library to version 0.5.1 or later to patch the vulnerability (reference: Affected versions and Fix sections).
*   Deploy a network intrusion detection system (NIDS) rule to detect SPDY frames with abnormally large `numSettings` values in `SETTINGS` frames (reference: Attack Chain step 2).
*   Implement rate limiting for SPDY connections to mitigate the impact of potential DoS attacks (reference: Overview and Impact sections).
*   Monitor application logs for out-of-memory errors related to `spdystream` to identify potential exploitation attempts (reference: Impact section).
