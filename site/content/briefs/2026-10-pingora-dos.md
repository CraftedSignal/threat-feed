---
title: Denial of Service via HTTP/2 Resource Exhaustion in Pingora
slug: 2026-10-pingora-dos
description: A vulnerability in Pingora versions prior to 0.8.1 allows unauthenticated remote attackers to trigger out-of-memory termination via HTTP/2 header-list and stream resource exhaustion.
date: "2026-10-20T02:32:34Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:cloudflare:pingora:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - network
vendors:
  - Cloudflare
products:
  - Pingora (< 0.8.1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated attacker can exploit this by sending specially crafted HTTP/2 frames, causing excessive memory consumption and leading to an out-of-memory (OOM) termination of the Pingora process.
    confidence_band: high
cves:
  - id: CVE-2026-105297
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105297
  - https://github.com/cloudflare/pingora/commit/d193c8d49b8b7c1c1ede93183759caa4f6906bbd
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade Pingora to version 0.8.1 or later
      owner: IT Operations
      due: 48h
      evidence: Mitigation section of source advisory
  mitigation_plan:
    - priority: immediate
      action: Explicitly configure max_header_list_size and max_concurrent_streams in application H2Options
      owner: Application Security
      addresses: CVE-2026-105297
      evidence: Mitigation section of source advisory
---

Pingora versions prior to 0.8.1 contain a vulnerability related to the default handling of HTTP/2 protocol limits. The server failed to enforce strict limits on decoded header-list sizes and the number of concurrent streams when specific application-level configurations were omitted. An unauthenticated remote attacker can exploit this by sending crafted 1-byte HPACK references, forcing the server to allocate hundreds of thousands of header fields per stream across an unlimited number of concurrent streams. By manipulating HTTP/2 flow control, an attacker can maintain these streams indefinitely, leading to rapid memory exhaustion. This behavior results in an out-of-memory (OOM) condition, forcing the termination of the Pingora process and resulting in a denial-of-service for the affected service. 

## Attack Chain

1. Attacker establishes a standard TCP connection to a server running a vulnerable Pingora instance.
2. Attacker initiates an HTTP/2 handshake (h2 or h2c).
3. Attacker opens multiple concurrent HTTP/2 streams leveraging the lack of server-side stream limiting.
4. Attacker sends a series of 1-byte HPACK references directed at a near-empty header field.
5. The Pingora server allocates massive numbers of header fields per stream to reconstruct the malicious headers.
6. Attacker uses HTTP/2 flow control mechanisms to keep the malicious streams open and active.
7. Server memory usage spikes until the operating system triggers an OOM-killer event for the Pingora process.
8. Service availability is lost for legitimate users.

## Impact

Successful exploitation results in a remote, unauthenticated denial-of-service. An attacker can crash a Pingora process with significant memory (e.g., 2 GiB) using a single connection. This vulnerability specifically impacts services terminating HTTP/2 traffic that rely on default Pingora configurations without explicitly setting `max_header_list_size` and `max_concurrent_streams`.

## Recommendation

* Upgrade all instances of Pingora to version 0.8.1 or later to implement default safety limits.
* For applications using custom `H2Options` that cannot be upgraded, manually configure `max_header_list_size` and `max_concurrent_streams` in the application source code immediately.
* Developers using Pingora 0.8.1 or later should leverage `pingora_core::protocols::http::v2::server::default_h2_options()` instead of `H2Options::default()` to ensure recommended limits are applied.
