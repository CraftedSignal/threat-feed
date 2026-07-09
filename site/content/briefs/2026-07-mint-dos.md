---
title: Mint HTTP/2 Client Unbounded Stream Map Growth Denial-of-Service (CVE-2026-48862)
slug: 2026-07-mint-dos
description: A malicious or compromised HTTP/2 server can exploit CVE-2026-48862 in Mint HTTP/2 clients by flooding them with PUSH_PROMISE frames and withholding corresponding HEADERS, leading to unbounded memory consumption and denial-of-service.
date: "2026-07-09T23:21:09Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - http/2
  - elixir
  - client-side
  - vulnerability
vendors:
  - elixir-mint
products:
  - Mint (>= 0.2.0, < 1.9.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A malicious or compromised HTTP/2 server can flood the client with PUSH_PROMISE frames and withhold the matching response HEADERS, pinning one map entry per frame indefinitely until the client process runs out of memory.
    confidence_band: high
cves:
  - id: CVE-2026-48862
    epss: 0.00384
references:
  - https://github.com/advisories/GHSA-g586-ccqf-7x4r
  - https://github.com/elixir-mint/mint/commit/65c6394d05a1b8aa4a7461708c3aa173e8d7a5cf
  - https://github.com/elixir-mint/mint/commit/70b97b6a5209fb288b0e04d8e657dda26c59de67
---

Elixir-Mint HTTP/2 client versions 0.2.0 through 1.8.x are vulnerable to a remote, unauthenticated denial-of-service attack, identified as CVE-2026-48862. A hostile or compromised HTTP/2 server can leverage this vulnerability by sending an excessive number of `PUSH_PROMISE` frames without following up with the matching `HEADERS`. Mint's client, by default, accepts `PUSH_PROMISE` frames and inserts entries into an internal connection stream map without properly enforcing the `max_concurrent_streams` limit, causing the map to grow indefinitely. This unbounded growth leads to linear memory consumption within the client process, eventually resulting in an out-of-memory (OOM) crash and denying service. This vulnerability affects any application using Mint as an HTTP/2 client, especially those connecting to untrusted or attacker-influenced servers, such as web backends, webhook delivery systems, and proxy components.

## Attack Chain

1. A malicious or compromised HTTP/2 server establishes a long-lived HTTP/2 connection with a vulnerable Mint client.
2. The Mint client sends its initial request `HEADERS` for a specific odd stream ID.
3. The malicious server captures the client's request stream ID.
4. The malicious server then sends a rapid flood of `PUSH_PROMISE` frames, each associated with the client's request stream ID.
5. Each `PUSH_PROMISE` frame specifies a new, unique even stream ID and carries a minimal HPACK-encoded header block.
6. The Mint client processes each `PUSH_PROMISE` frame, adding a `:reserved_remote` entry into its `conn.streams` map for every promised stream ID without consulting `max_concurrent_streams`.
7. The malicious server intentionally withholds the corresponding response `HEADERS` for all the promised stream IDs.
8. As the `conn.streams` map grows linearly with each unfulfilled `PUSH_PROMISE` frame, the Mint client's process consumes an increasing amount of memory until it crashes due to an Out-Of-Memory (OOM) error.

## Impact

Successful exploitation of CVE-2026-48862 results in a remote, unauthenticated denial-of-service against any process utilizing Mint as an HTTP/2 client when connecting to an untrusted or attacker-controlled server. Since HTTP/2 server push is enabled by default in Mint, no specific application opt-in is required for the vulnerability to be exploitable. Affected systems include outbound HTTP/2 clients in web backends, webhook delivery services, data scrapers, federated components, and proxy services that interact with external HTTP/2 origins. An attacker can crash the client process, rendering the service unavailable and potentially requiring manual intervention to restore.

## Recommendation

* Upgrade all affected Mint HTTP/2 clients to version 1.9.0 or newer immediately to mitigate CVE-2026-48862.
* For systems that cannot be immediately upgraded, disable HTTP/2 server push on connections to untrusted servers by explicitly passing `client_settings: [enable_push: false]` to the `'Elixir.Mint.HTTP':connect/4` function as a workaround for CVE-2026-48862.
