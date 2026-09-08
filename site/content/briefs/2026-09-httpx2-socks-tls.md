---
title: Plaintext WebSocket Exposure in HTTPX2 and httpcore2 via SOCKS5 Proxy
slug: 2026-09-httpx2-socks-tls
description: A transport flaw in httpcore2 and httpx2 fails to establish TLS for wss:// connections routed through SOCKS5 proxies, exposing authentication headers, cookies, and message payloads in plaintext to proxy intermediaries.
date: "2026-09-08T21:53:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - transport-security
  - proxy
vendors:
  - encode
products:
  - httpcore2 (< 2.10.0)
  - httpx2 (2.6.0-2.9.1)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: The synchronous and asynchronous SOCKS5 connection implementations upgrade the established proxy tunnel to TLS only when the remote origin scheme is https.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1572
    technique_name: Protocol Tunneling
    evidence: A malicious or compromised SOCKS proxy can accept the SOCKS connection, observe the plaintext handshake... and then read or modify WebSocket frames in both directions.
    confidence_band: high
cves:
  - id: CVE-2026-84381
    cvss: 8.1
    epss: 0.00079
references:
  - https://github.com/advisories/GHSA-7mj9-2mp8-4m2p
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84381
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade httpcore2 and httpx2 to 2.10.0 or later
      owner: IT Operations
      due: 48h
      evidence: 'Mitigation: Upgrade HTTPX2 and httpcore2 to 2.10.0 or later.'
  mitigation_plan:
    - priority: immediate
      action: Route wss:// connections directly, bypassing SOCKS proxies
      owner: Application Security
      addresses: CVE-2026-84381
      evidence: If upgrading is not immediately possible, do not route wss:// connections through a SOCKS proxy.
---

The Python libraries httpcore2 (releases prior to 2.10.0) and httpx2 (releases 2.6.0 through 2.9.1) contain a security vulnerability where TLS is not correctly initialized for secure WebSocket (`wss://`) connections routed through SOCKS5 proxies. The SOCKS5 connection implementation includes a check to upgrade to TLS only for `https` origins, failing to include `wss` in the logic. Consequently, the client transmits the WebSocket opening handshake and all subsequent frames in plaintext through the proxy. This vulnerability, tracked as CVE-2026-84381, violates RFC 6455 requirements for secure WebSocket communication, rendering the transport susceptible to interception, modification, and server impersonation by any actor controlling or observing the SOCKS proxy path.

## Impact

Successful exploitation allows a malicious or compromised SOCKS proxy to intercept sensitive information, including URL query parameters, authentication tokens in Authorization headers, and session cookies. Furthermore, because the TLS handshake is bypassed, the client fails to verify the server's certificate, enabling an attacker to perform man-in-the-middle attacks by impersonating the target server and injecting or altering application-level WebSocket messages.

## Recommendation

* Upgrade all instances of `httpx2` and `httpcore2` to version `2.10.0` or later.
* If upgrading is not immediately possible, modify application configuration to bypass SOCKS proxies for all `wss://` connections.
* Review application logs for WebSocket traffic originating from servers configured to use SOCKS5 proxies to identify potential exposure.
* Patch CVE-2026-84381 across all environments utilizing affected versions of the HTTPX2 library.
