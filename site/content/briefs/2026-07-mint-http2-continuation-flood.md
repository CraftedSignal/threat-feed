---
title: Mint HTTP/2 Client Vulnerable to Unbounded CONTINUATION Frame Accumulation (CVE-2026-49754)
slug: 2026-07-mint-http2-continuation-flood
description: A malicious or compromised HTTP/2 server can exploit CVE-2026-49754 in the Elixir Mint HTTP/2 client by sending an endless chain of CONTINUATION frames without an END_HEADERS flag, leading to unbounded memory accumulation, process exhaustion, and remote unauthenticated denial-of-service.
date: "2026-07-09T23:21:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - http/2
  - denial-of-service
  - vulnerability
  - elixir
  - mint
vendors:
  - Elixir Mint
products:
  - Mint (< 1.9.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A malicious or compromised HTTP/2 server can drive the client's memory to arbitrary size by streaming an endless chain of `CONTINUATION` frames after a `HEADERS` frame that omits `END_HEADERS`, causing memory exhaustion and BEAM process death.
    confidence_band: high
cves:
  - id: CVE-2026-49754
    epss: 0.00384
references:
  - https://github.com/advisories/GHSA-2p26-p43x-fhp8
  - https://github.com/elixir-mint/mint/commit/596ca4304504be68939c4929e0831557097962b8
  - https://github.com/elixir-mint/mint/commit/b662d127d3028b5426c88d4c9cc7fe430491a10b
---

The Elixir Mint HTTP/2 client is vulnerable to a denial-of-service attack (CVE-2026-49754) due to an unbounded accumulation of `CONTINUATION` header-block fragments. This vulnerability, disclosed by GHSA, allows a malicious or compromised HTTP/2 server to exhaust the client's memory. By streaming an endless sequence of `CONTINUATION` frames following an initial `HEADERS` frame that lacks the `END_HEADERS` flag, an attacker can drive the client's process memory to arbitrary size. This flaw affects Mint versions prior to 1.9.0 and requires no specific client-side configuration, making the default Mint client susceptible. A single connection to an attacker-controlled HTTP/2 endpoint is sufficient to trigger memory exhaustion and ultimately crash the BEAM process, resulting in a remote, unauthenticated denial-of-service.

## Attack Chain

1. A victim application using the Elixir Mint HTTP/2 client establishes an HTTP/2 connection to a server.
2. The client sends an HTTP/2 `HEADERS` frame as part of a request to the server.
3. An attacker-controlled or compromised HTTP/2 server receives the client's request.
4. The malicious server responds to the client's request by sending a `HEADERS` frame on stream 1, deliberately setting `flags = 0` (omitting `END_HEADERS` and `END_STREAM`) and including an empty header-block fragment.
5. The malicious server then continuously streams `CONTINUATION` frames on stream 1, each with `flags = 0` and a payload up to the peer-advertised `SETTINGS_MAX_FRAME_SIZE`, never setting `END_HEADERS`.
6. The Mint client's HTTP/2 receive path, specifically the `'Elixir.Mint.HTTP2':handle_continuation/3` function, continuously appends these `CONTINUATION` fragments to the `conn.headers_being_processed` buffer.
7. Due to the absence of per-stream size caps or `CONTINUATION` frame-count caps, the client's process memory grows linearly and uncontrollably with the incoming flood of `CONTINUATION` frames.
8. The unbounded memory growth eventually leads to memory exhaustion and an Out-Of-Memory (OOM) error, causing the entire Elixir BEAM process running the Mint client to crash, resulting in a denial-of-service.

## Impact

The successful exploitation of CVE-2026-49754 results in a remote, unauthenticated denial-of-service against any application utilizing the Elixir Mint HTTP/2 client to connect to an untrusted or attacker-influenced server. A single connection is sufficient for an attacker to drive the client's memory to an arbitrary size, leading to the crash of the underlying BEAM process. This can incapacitate critical services or applications relying on Mint for HTTP/2 communication, causing significant operational disruption and data unavailability. The default Mint configuration is vulnerable, requiring no specific client-side opt-in for exploitation. The vulnerability has been scored CVSS v4.0 8.2 (HIGH).

## Recommendation

* Upgrade the Elixir Mint library to version 1.9.0 or later to patch CVE-2026-49754.
* If immediate patching is not possible, restrict Mint to HTTP/1 for connections to untrusted servers by passing `protocols: [:http1]` to `'Elixir.Mint.HTTP':connect/4` to avoid the vulnerable HTTP/2 receive path, as outlined in the workarounds.
